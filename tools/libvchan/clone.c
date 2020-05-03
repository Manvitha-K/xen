#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <xen/types.h>
#include <regex.h>

#include <libxl.h>
#include <libxl_utils.h>
#include <libxlutil.h>

#include <xl.h>
#include <xl_utils.h>
#include <xl_parse.h>
#include <xentoollog.h>
#include <libxenvchan.h>

int libxenvchan_write_all(struct libxenvchan *ctrl, char *buf, int size)
{
	int written = 0;
	int ret;
	while (written < size) {
		ret = libxenvchan_write(ctrl, buf + written, size - written);
		if (ret <= 0) {
			perror("write");
			exit(1);
		}
		written += ret;
	}
	return size;
}

int write_all(int fd, char *buf, int size)
{
	int written = 0;
	int ret;
	while (written < size) {
		ret = write(fd, buf + written, size - written);
		if (ret <= 0) {
			perror("write");
			exit(1);
		}
		written += ret;
	}
	return size;
}

void usage(char** argv)
{
	fprintf(stderr, "usage:\n"
		"%s [client|server] [read|write] domid nodepath\n", argv[0]);
	exit(1);
}


#define BUFSIZE 5000
char buf[BUFSIZE];

libxl_ctx *ctx;
char *lockfile;
xentoollog_logger_stdiostream *logger;

static int auto_autoballoon(void)
{
    const libxl_version_info *info;
    regex_t regex;
    int ret;

    info = libxl_get_version_info(ctx);
    if (!info)
        return 1; /* default to on */

    ret = regcomp(&regex,
                  "(^| )dom0_mem=((|min:|max:)[0-9]+[bBkKmMgG]?,?)+($| )",
                  REG_NOSUB | REG_EXTENDED);
    if (ret)
        return 1;

    ret = regexec(&regex, info->commandline, 0, NULL, 0);
    regfree(&regex);
    return ret == REG_NOMATCH;
}

void vchan_parse_global_config(const char *configfile,
                              const char *configfile_data,
                              int configfile_len)
{
    long l;
    XLU_Config *config;
    int e;
    const char *buf;

    config = xlu_cfg_init(stderr, configfile);
    if (!config) {
        fprintf(stderr, "Failed to allocate for configuration\n");
        exit(1);
    }

    e = xlu_cfg_readdata(config, configfile_data, configfile_len);
    if (e) {
        fprintf(stderr, "Failed to parse config file: %s\n", strerror(e));
        exit(1);
    }

    if (!xlu_cfg_get_string(config, "autoballoon", &buf, 0)) {
        if (!strcmp(buf, "on") || !strcmp(buf, "1"))
            autoballoon = 1;
        else if (!strcmp(buf, "off") || !strcmp(buf, "0"))
            autoballoon = 0;
        else if (!strcmp(buf, "auto"))
            autoballoon = -1;
        else
            fprintf(stderr, "invalid autoballoon option");
    }
    if (autoballoon == -1)
        autoballoon = auto_autoballoon();

    if (!xlu_cfg_get_long (config, "run_hotplug_scripts", &l, 0))
        run_hotplug_scripts = l;

    if (!xlu_cfg_get_string (config, "lockfile", &buf, 0))
        lockfile = strdup(buf);
    else {
        lockfile = strdup(XL_LOCK_FILE);
    }

    if (!lockfile) {
        fprintf(stderr, "failed to allocate lockfile\n");
        exit(1);
    }

    /*
     * For global options that are related to a specific type of device
     * we use the following nomenclature:
     *
     * <device type>.default.<option name>
     *
     * This allows us to keep the default options classified for the
     * different device kinds.
     */

    if (!xlu_cfg_get_string (config, "vifscript", &buf, 0)) {
        fprintf(stderr, "the global config option vifscript is deprecated, "
                        "please switch to vif.default.script\n");
        free(default_vifscript);
        default_vifscript = strdup(buf);
    }

    if (!xlu_cfg_get_string (config, "vif.default.script", &buf, 0)) {
        free(default_vifscript);
        default_vifscript = strdup(buf);
    }

    if (!xlu_cfg_get_string (config, "defaultbridge", &buf, 0)) {
        fprintf(stderr, "the global config option defaultbridge is deprecated, "
                        "please switch to vif.default.bridge\n");
        free(default_bridge);
        default_bridge = strdup(buf);
    }

    if (!xlu_cfg_get_string (config, "vif.default.bridge", &buf, 0)) {
        free(default_bridge);
        default_bridge = strdup(buf);
    }

    if (!xlu_cfg_get_string (config, "vif.default.gatewaydev", &buf, 0))
        default_gatewaydev = strdup(buf);

    if (!xlu_cfg_get_string (config, "vif.default.backend", &buf, 0))
        default_vifbackend = strdup(buf);

    if (!xlu_cfg_get_string (config, "output_format", &buf, 0)) {
        if (!strcmp(buf, "json"))
            default_output_format = OUTPUT_FORMAT_JSON;
        else if (!strcmp(buf, "sxp"))
            default_output_format = OUTPUT_FORMAT_SXP;
        else {
            fprintf(stderr, "invalid default output format \"%s\"\n", buf);
        }
    }
    if (!xlu_cfg_get_string (config, "blkdev_start", &buf, 0))
        blkdev_start = strdup(buf);

    if (!xlu_cfg_get_long (config, "claim_mode", &l, 0))
        claim_mode = l;

    xlu_cfg_replace_string (config, "remus.default.netbufscript",
        &default_remus_netbufscript, 0);
    xlu_cfg_replace_string (config, "colo.default.proxyscript",
        &default_colo_proxy_script, 0);

    e = xlu_cfg_get_bounded_long (config, "max_grant_frames", 0, INT_MAX,
                                  &l, 1);
    if (!e)
        max_grant_frames = l;
    else if (e != ESRCH)
        exit(1);

    e = xlu_cfg_get_bounded_long (config, "max_maptrack_frames", 0,
                                  INT_MAX, &l, 1);
    if (!e)
        max_maptrack_frames = l;
    else if (e != ESRCH)
        exit(1);

    libxl_cpu_bitmap_alloc(ctx, &global_vm_affinity_mask, 0);
    libxl_cpu_bitmap_alloc(ctx, &global_hvm_affinity_mask, 0);
    libxl_cpu_bitmap_alloc(ctx, &global_pv_affinity_mask, 0);

    if (!xlu_cfg_get_string (config, "vm.cpumask", &buf, 0))
        parse_cpurange(buf, &global_vm_affinity_mask);
    else
        libxl_bitmap_set_any(&global_vm_affinity_mask);
    if (!xlu_cfg_get_string (config, "vm.hvm.cpumask", &buf, 0))
        parse_cpurange(buf, &global_hvm_affinity_mask);
    else
       libxl_bitmap_set_any(&global_hvm_affinity_mask);
    if (!xlu_cfg_get_string (config, "vm.pv.cpumask", &buf, 0))
        parse_cpurange(buf, &global_pv_affinity_mask);
    else
        libxl_bitmap_set_any(&global_pv_affinity_mask);

    if (!xlu_cfg_get_string (config, "domid_policy", &buf, 0)) {
        if (!strcmp(buf, "xen"))
            domid_policy = INVALID_DOMID;
        else if (!strcmp(buf, "random"))
            domid_policy = RANDOM_DOMID;
        else
            fprintf(stderr, "invalid domid_policy option");
    }

    xlu_cfg_destroy(config);
}




void vchan_ctx_free(void){
	libxl_bitmap_dispose(&global_pv_affinity_mask);
	libxl_bitmap_dispose(&global_hvm_affinity_mask);
	libxl_bitmap_dispose(&global_vm_affinity_mask);
	if (ctx) {
		libxl_ctx_free(ctx);
		ctx = NULL;
	}
	if (logger) {
		xtl_logger_destroy((xentoollog_logger*)logger);
		logger = NULL;
	}
	if (lockfile) {
        free(lockfile);
        lockfile = NULL;
    }
}

void checkpoint_invoke(uint32_t domid){
	const char *filename = "checkpoint";
    	const char *config_filename = NULL;
	void *config_data = 0;
	int config_len = 0; 
    	int checkpoint = 0;
    	int leavepaused = 0;
	int preserve_domid = 0;
    	int ret;
	fprintf(stderr, "domid:\n" "%u \n",domid);
	logger = xtl_createlogger_stdiostream(stderr, XTL_NONE, 0);
        if (!logger) 
	   exit(EXIT_FAILURE);

    	xl_ctx_alloc();
    	atexit(vchan_ctx_free);
	ret = save_domain(domid, preserve_domid, filename, checkpoint, leavepaused, config_filename);
}



void reader_clone(struct libxenvchan *ctrl)
{
	int size;
	for (;;) {
		size = rand() % (BUFSIZE - 1) + 1;
		size = libxenvchan_read(ctrl, buf, size);
		//fprintf(stderr, "#");
		if (size < 0) {
			perror("read vchan");
			libxenvchan_close(ctrl);
			exit(1);
		}
		buf[size] = '\0';
		if(strncmp(buf,"CLONE", 6)==0){
			//checkpoint_invoke((uint32_t)(buf[7]));
			checkpoint_invoke((uint32_t)(8));
			exit(1);
		}

	}
}

void writer_clone(struct libxenvchan *ctrl, char* domId)
{
	int size;
	for (;;) {
		char buff[6] = "CLONE";
		//strcat(buff, domId);
		size = strlen(buff);
		
		size = libxenvchan_write_all(ctrl, buff, size);
		
		break;//todo: make sure all buf data is written before breaking. assuming that libxenvchan_write writes all of buff[6] to the shared memory. see whether size=0 or size=6 for successful write op
		//fprintf(stderr, "#");
		if (size < 0) {
			perror("vchan write");
			exit(1);
		}
		if (size == 0) {
			perror("write size=0?\n");
			exit(1);
		}
	}
	fprintf(stderr,"\nREACHES HERE");
}


/**
	Simple libxenvchan application, both client and server.
	One side does writing, the other side does reading; both from
	standard input/output fds.
*/
int main(int argc, char **argv)
{
	int seed = time(0);
	struct libxenvchan *ctrl = 0;
	int wr = 0;
	if (argc < 4)
		usage(argv);
	if (!strcmp(argv[2], "read"))
		wr = 0;
	else if (!strcmp(argv[2], "write")){
		if (argc < 5)
			usage(argv);
		wr = 1;
	}
	else
		usage(argv);
	if (!strcmp(argv[1], "server"))
		ctrl = libxenvchan_server_init(NULL, atoi(argv[3]), argv[4], 0, 0);
	else if (!strcmp(argv[1], "client"))
		ctrl = libxenvchan_client_init(NULL, atoi(argv[3]), argv[4]);
	else
		usage(argv);
	if (!ctrl) {
		perror("libxenvchan_*_init");
		exit(1);
	}
	ctrl->blocking = 1;

	srand(seed);
	fprintf(stderr, "seed=%d\n", seed);
	if (wr)
		writer_clone(ctrl, argv[5]);
	else
		reader_clone(ctrl);
	libxenvchan_close(ctrl);
	return 0;
}
