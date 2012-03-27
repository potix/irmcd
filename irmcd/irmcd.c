#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <sysexits.h>
#include <libgen.h>
#include <signal.h>
#include <event.h>
#include <syslog.h>

#include "debug.h"
#include "common.h"
#include "logger.h"
#include "config.h"
#include "controller.h"
#include "tcp_sock.h"
#include "string_util.h"

#define DEFAULT_CONF_FILE "/etc/irmcd.conf"
#define CONFIG_KEY_VERBOSE "verbose"
#define CONFIG_KEY_LOG_TYPE "logType"
#define DEFAULT_LOG_TYPE "syslog"
#define CONFIG_KEY_LOG_PATH "logPath"
#define DEFAULT_LOG_PATH "/var/log/irmcd"
#define DEFAULT_VERBOSE "false"
#define CONFIG_KEY_FOREGROUND "foreground"
#define DEFAULT_FOREGROUND "false"
#define CONFIG_KEY_PID_FILE "pidFile"
#define DEFAULT_PID_FILE "/var/run/irmcd.pid"
#define CONFIG_KEY_BIND_ADDR "bindAddress"
#define DEFAULT_BIND_ADDR "127.0.0.1"
#define CONFIG_KEY_BIND_PORT "bindPort"
#define DEFAULT_BIND_PORT "10023"

#define LOG_FACILITY LOG_DAEMON

struct irmcd {
	const char *config_file;
	int verbose;
	int foreground;
	int keepalive;
	char pid_file[MAXPATHLEN];
	char log_type[16];
	char log_path[MAXPATHLEN / 2];
	char bind_addr[NI_MAXHOST];
	char bind_port[NI_MAXSERV];
	struct event_base *event_base;
	sigset_t sigfillmask;
	sigset_t sigmask;
	struct event sigterm_event;
	struct event sigint_event;
	struct event sighup_event;
	tcp_server_t *tcp_server;
	controller_t *controller;
};

static void
init_irmcd(
    struct irmcd *irmcd)
{
	ASSERT(irmcd != NULL);
	memset(irmcd, 0, sizeof(struct irmcd));
	irmcd->config_file = DEFAULT_CONF_FILE;
}

static int
load_config(
    struct irmcd *irmcd,
    int initialize)
{
        config_t *config = NULL;

	ASSERT(irmcd != NULL);
	ASSERT((initialize == 0 || initialize == 1));
        if (config_create(&config, irmcd->config_file)) {
                logging(LOG_LV_ERR, "failed in create cofig in %s", __func__);
		goto fail;
        }
        if (config_load(config)) {
                logging(LOG_LV_ERR, "failed in load config in %s", __func__);
		goto fail;
        }
	if (initialize) {
		if (config_get_bool(
		    config,
		    &irmcd->foreground,
		    CONFIG_SECTION_GLOBAL_SETTING,
		    CONFIG_KEY_FOREGROUND,
		    DEFAULT_FOREGROUND)) {
			logging(LOG_LV_ERR, "failed in get foreground path in %s", __func__);
			goto fail;
		}
		if (config_get_string(
		    config,
		    irmcd->pid_file,
		    sizeof(irmcd->pid_file),
		    CONFIG_SECTION_GLOBAL_SETTING,
		    CONFIG_KEY_PID_FILE,
		    DEFAULT_PID_FILE,
		    sizeof(irmcd->pid_file) - 1)) {
			logging(LOG_LV_ERR, "failed in get pid file in %s", __func__);
			goto fail;
		}
		if (config_get_string(
		    config,
		    irmcd->log_type,
		    sizeof(irmcd->log_type),
		    CONFIG_SECTION_GLOBAL_SETTING,
		    CONFIG_KEY_LOG_TYPE,
		    DEFAULT_LOG_TYPE,
		    sizeof(irmcd->log_type) - 1)) {
			logging(LOG_LV_ERR, "failed in get log type in %s", __func__);
			goto fail;
		}
		if (config_get_string(
		    config,
		    irmcd->log_path,
		    sizeof(irmcd->log_path),
		    CONFIG_SECTION_GLOBAL_SETTING,
		    CONFIG_KEY_LOG_PATH,
		    DEFAULT_LOG_PATH,
		    sizeof(irmcd->log_path) - 1)) {
			logging(LOG_LV_ERR, "failed in get log path in %s", __func__);
			goto fail;
		}
	}
        if (config_get_bool(
            config,
            &irmcd->verbose,
	    CONFIG_SECTION_GLOBAL_SETTING,
            CONFIG_KEY_VERBOSE,
	    DEFAULT_VERBOSE)) {
                logging(LOG_LV_ERR, "failed in get verbose in %s", __func__);
		goto fail;
        }
        if (config_get_address(
            config,
            irmcd->bind_addr,
            sizeof(irmcd->bind_addr),
	    CONFIG_SECTION_GLOBAL_SETTING,
            CONFIG_KEY_BIND_ADDR,
	    DEFAULT_BIND_ADDR)) {
                logging(LOG_LV_ERR, "failed in get bind address in %s", __func__);
		goto fail;
        }
        if (config_get_port(
            config,
            irmcd->bind_port,
            sizeof(irmcd->bind_port),
	    CONFIG_SECTION_GLOBAL_SETTING,
            CONFIG_KEY_BIND_PORT,
	    DEFAULT_BIND_PORT)) {
                logging(LOG_LV_ERR, "failed in get bind port in %s", __func__);
		goto fail;
        }
        if (config_destroy(config)) {
		logging(LOG_LV_ERR, "failed in destroy config in %s", __func__);
		goto fail;
        }

	return 0;

fail:
	if (config) {
		config_destroy(config);
	}

	return 1;
}

static int
parse_args(
    struct irmcd *irmcd,
    int argc,
    char **argv)
{
        int opt;
	char cmd[MAXPATHLEN];

        ASSERT(irmcd != NULL);
        ASSERT(argv != NULL);
	STRLCPY(cmd, argv[0], sizeof(cmd));
        while ((opt = getopt(argc, argv, "c:h")) != -1) {
                switch (opt) {
                case 'c':
                        irmcd->config_file = optarg;
                        break;
                case 'h':
			fprintf(stderr, "usage: %s [-c <config_file>][-h]\n", basename(cmd));
			return 1;
                default:
                        return 1;
                }
        }

        return 0;
}

static int
make_pidfile(
    const char *pid_file)
{
        FILE *fp;

	ASSERT(pid_file != NULL);
        if (pid_file == NULL) {
                errno = EINVAL;
                return 1;
        }
        if (access(pid_file, R_OK|W_OK) == 0) {
                errno = EEXIST;
                return 1;
        }
        fp = fopen(pid_file, "w+");
        if (fp == NULL) {
                return 1;
        }
        fprintf(fp, "%d\n", getpid());
        fclose(fp);

        return 0;
}

static void
terminate(
    int fd,
    short event,
    void *args)
{
        struct irmcd *irmcd = args;

	ASSERT(args != NULL);
	ASSERT(event == EV_SIGNAL);

	/* 停止処理 */
        tcp_server_stop(irmcd->tcp_server);
	logging(LOG_LV_INFO, "tcp server stop in %s", __func__);
	controller_stop(irmcd->controller);
	logging(LOG_LV_INFO, "controller stop in %s", __func__);
        event_del(&irmcd->sigterm_event);
        event_del(&irmcd->sigint_event);
        event_del(&irmcd->sighup_event);
}

static void
reload(int fd, short event, void *args)
{
        struct irmcd *irmcd = args;
	char backup_bind_addr[NI_MAXHOST];
	char backup_bind_port[NI_MAXSERV];

	ASSERT(args != NULL);
	ASSERT(event == EV_SIGNAL);

	/* 変化をチェックするためのbackup */
        strcpy(backup_bind_addr, irmcd->bind_addr);
        strcpy(backup_bind_port, irmcd->bind_port);

	/* 設定の再読み込み */
        load_config(irmcd, 0);

	/* tcp server 再起動処理 */
	if (strcmp(irmcd->bind_addr, backup_bind_addr) != 0 ||
	    strcmp(irmcd->bind_port, backup_bind_port) != 0) {
		tcp_server_stop(irmcd->tcp_server);
		if (tcp_server_start(
		    &irmcd->tcp_server,
		    irmcd->controller,
		    irmcd->event_base,
		    irmcd->bind_addr,
		    irmcd->bind_port)) {
			logging(
			    LOG_LV_ERR,
			    "failed in starting tcp server in %s",
			    __func__);
			exit(EX_OSERR);
		}
	} 
}

int
main(
    int argc,
    char *argv[])
{
        struct irmcd irmcd;
	int result = EX_OK;
	char cmd_path[MAXPATHLEN];
	char *cmd_ptr;

	STRLCPY(cmd_path, argv[0], sizeof(cmd_path));
	cmd_ptr = basename(cmd_path);

        init_irmcd(&irmcd);

	/* コンフィグが読み込まれるまでは stderrに出力 */
	if (logger_create()) {
		fprintf(stderr, "failed in create logger");
		result = EX_OSERR;
		goto last;
	}
	if (logger_open(
		LOG_LV_INFO,
		LOG_TYPE_STR_STDERR,
		cmd_ptr,
		LOG_PID,
		LOG_STR_DAEMON,
		NULL)) {
		fprintf(stderr, "failed in open logger");
		result = EX_OSERR;
		goto last;
	}

	/* コマンドパース */
	if (parse_args(&irmcd, argc, argv)) {
		result = EX_USAGE;
		goto last;
	}

	/* コンフィグ読み込み */
	if (load_config(&irmcd, 1)) {
		logging(LOG_LV_ERR, "failed in load config in %s", __func__);
		result = EX_OSERR;
		goto last;
	}

	/* コンフィグが読み込まれたのでコンフィグ指定のものに変更 */
	logger_close();
	logger_destroy();
	if (logger_create()) {
		fprintf(stderr, "failed in create logger");
		result = EX_OSERR;
		goto last;
	}
	if (logger_open(
		LOG_LV_INFO,
		irmcd.log_type,
		cmd_ptr,
		LOG_PID,
		LOG_STR_DAEMON,
		irmcd.log_path)) {
		fprintf(stderr, "failed in open logger");
		result = EX_OSERR;
		goto last;
	}

	/* デーモン化 */
        if (!irmcd.foreground) {
                if (daemon(1, 1)) {
                        logging(LOG_LV_ERR, "failed in start daemon in %s", __func__);
			result = EX_OSERR;
                	goto last;
                }
        }
	
	/* プロセスIDファイル作成 */
        if (make_pidfile(irmcd.pid_file)) {
                logging(LOG_LV_ERR,
		    "failed in make process id file (%s) in %s",
		    irmcd.pid_file,
		    __func__);
		closelog();
		return EX_OSERR;
        }

	/* event baseの初期化 */
        irmcd.event_base = event_init();

	/*  controllerを作って動かす */
        sigfillset(&irmcd.sigfillmask);
        pthread_sigmask(SIG_BLOCK, &irmcd.sigfillmask, &irmcd.sigmask);
	if (controller_create(
	    &irmcd.controller,
            irmcd.config_file)) {
                logging(LOG_LV_ERR, "failed in create contoller in %s", __func__);
		result = EX_OSERR;
                goto last;
	}
	if (controller_start(
	    irmcd.controller)) {
                logging(LOG_LV_ERR, "failed in start contoller in %s", __func__);
                goto last;
	}
	logging(LOG_LV_INFO, "controller start in %s", __func__);
	
	/* main thread のシグナルを設定 */
        sigaddset(&irmcd.sigmask, SIGPIPE);
        pthread_sigmask(SIG_SETMASK, &irmcd.sigmask, NULL);
        signal_set(&irmcd.sigterm_event, SIGTERM, terminate, &irmcd);
        event_base_set(irmcd.event_base, &irmcd.sigterm_event);
        signal_add(&irmcd.sigterm_event, NULL);
        signal_set(&irmcd.sigint_event, SIGINT, terminate, &irmcd);
        event_base_set(irmcd.event_base, &irmcd.sigint_event);
        signal_add(&irmcd.sigint_event, NULL);
        signal_set(&irmcd.sighup_event, SIGHUP, reload, &irmcd);
        event_base_set(irmcd.event_base, &irmcd.sighup_event);
        signal_add(&irmcd.sighup_event, NULL);

	/* tcp サーバー起動 */
	if (tcp_server_start(
	    &irmcd.tcp_server,
	    irmcd.controller,
	    irmcd.event_base,
	    irmcd.bind_addr,
	    irmcd.bind_port)) {
                logging(LOG_LV_ERR, "failed in starting tcp server in %s", __func__);
                result = EX_OSERR;
		goto last;
	}
	logging(LOG_LV_INFO, "tcp server start in %s", __func__);

	/* main threadのevent loop */
        if (event_base_dispatch(irmcd.event_base) == -1) {
                logging(LOG_LV_ERR, "failed in event base dispatch in %s", __func__);
                result = EX_OSERR;
		goto last;
	}

last:
	/* 後始末 */
	if (irmcd.controller) {
		controller_destroy(irmcd.controller);
	}
	if (irmcd.event_base) {
		event_base_free(irmcd.event_base);
	}
	if (irmcd.pid_file[0] != '\0') {
		unlink(irmcd.pid_file);
	}
	logger_close();
	logger_destroy();
	

	return result;
}
