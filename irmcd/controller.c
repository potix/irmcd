#include <sys/types.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sysexits.h>
#include <event.h>
#include <regex.h>
#include <pthread.h>
#include <netdb.h>
#include <pcre.h>

#include "debug.h"
#include "common.h"
#include "logger.h"
#include "controller.h"
#include "queue.h"
#include "config.h"
#include "buffer_manager.h"
#include "string_util.h"

#define MAX_LINE_BUFFER CONFIG_LINE_BUF
#define NEW_LINE_CRLF	"\r\n"
#define NEW_LINE_LF	"\n"
#define CONF_KEY_MSG_REGEX		"messageRegex"
#define CONF_KEY_VARIABLES_NAME		"variablesName"
#define CONF_KEY_CNTRL_ACTIVE		"controllerActive"
#define CONF_KEY_SCENARIO_FILE		"scenarioFile"
#define CONF_KEY_CONNECT_ADDR		"connectAddr"
#define CONF_KEY_CONNECT_PORT		"connectPort"
#define CONF_KEY_EXECUTE_SCRIPT		"executeScript"
#define CONF_KEY_NEW_LINE		"newLine"
#define CONF_KEY_REQUEST_COMMAND	"requestCommand"
#define CONF_KEY_RESPONSE_REGEX		"responseRegex"
#define CONF_KEY_EXPECT_REGEX		"expectRegex"
#define CONF_KEY_BEFORE_WAIT		"beforeWait"
#define CONF_KEY_IDLE_TIMEOUT		"idleTimeout"
#define CONF_KEY_REPEAT_COUNT		"repeatCount"
#define CONF_KEY_PERIODIC_INTERVAL	"periodicInterval"
#define CONF_KEY_IGNORE_ERROR		"ignoreError"
#define CONF_VALUE_NEW_LINE_CRLF	"CRLF"
#define CONF_VALUE_NEW_LINE_LF		"LF"
#define CONF_VALUE_NEW_LINE_MAX		4
#define MIN_BEFORE_WAIT 0
#define MAX_BEFORE_WAIT 60
#define DEFAULT_BEFORE_WAIT 1;
#define DEFAULT_BEFORE_WAIT_STR "1"
#define MIN_IDLE_TIMEOUT 0
#define MAX_IDLE_TIMEOUT 600
#define DEFAULT_IDLE_TIMEOUT 120;
#define DEFAULT_IDLE_TIMEOUT_STR "120"
#define MIN_PERIODIC_INTERVAL 0
#define MAX_PERIODIC_INTERVAL 120 
#define DEFAULT_PERIODIC_INTERVAL 60
#define DEFAULT_PERIODIC_INTERVAL_STR "60"
#define MIN_REPEAT_COUNT 0
#define MAX_REPEAT_COUNT 100
#define DEFAULT_REPEAT_COUNT 0
#define DEFAULT_REPEAT_COUNT_STR "0"
#ifndef MAX_QUEUE_SIZE
#define MAX_QUEUE_SIZE	1000
#endif
#ifndef MAX_MATCH
#define MAX_MATCH 6
#endif
#ifndef SHELL
#define SHELL "/bin/sh"
#endif
#define SCRIPT_RESULT_SUCCESS	"sccess"
#define SCRIPT_RESULT_FAIL	"fail"

struct controller_variable {
	char name[MAX_LINE_BUFFER];
	char value[MAX_LINE_BUFFER];
};
typedef struct controller_variable controller_variable_t;

struct controller_command_arg {
	struct timeval idle_timeout;
	struct event idle_timeout_event;
	struct timeval periodic_interval;
	struct event periodic_event;
	int repeat_count;
	struct event read_event;
	struct event write_event;
	char req_cmd_buff[(MAX_LINE_BUFFER * 2) + 2 /* newline */];
	int req_cmd_buff_len;
	int req_cmd_write_len;
	char res_cmd_buff[(MAX_LINE_BUFFER * 2) + 2 /* newline */];
	int res_cmd_buff_len;
	char res_regex_buff[(MAX_LINE_BUFFER * 2)];
	int res_regex_buff_len;
	char expect_regex_buff[(MAX_LINE_BUFFER * 2)];
	int expect_regex_buff_len;
	int ignore_error;
};
typedef struct controller_command_arg controller_command_arg_t;

struct controller_procinfo {
	char request[MAX_LINE_BUFFER];
	controller_variable_t variable[MAX_MATCH];
	char section[MAX_LINE_BUFFER];
	char scenario_file[MAX_LINE_BUFFER];
	char connect_addr[MAX_LINE_BUFFER];
	char connect_port[MAX_LINE_BUFFER];
	char exec_script[MAX_LINE_BUFFER];
	int controller_active;
        const char *new_line;
	int error;
	int socket;
	config_t *config;
	config_t *scenario;
	controller_command_arg_t cmd_arg;
	controller_t *controller;
};
typedef struct controller_procinfo controller_procinfo_t;

struct controller {
	int active;
	char *config_file;
	buffer_manager_t *procinfo_buffer;
	queue_t *queue;
	pthread_t thread;
	int main_run;
	struct event_base *event_base;
};

static void
controller_free_procinfo(
    controller_procinfo_t *controller_procinfo)
{
	ASSERT(controller_procinfo != NULL);
	if (controller_procinfo->socket != -1) {
		close(controller_procinfo->socket);
	}
	if (controller_procinfo->scenario) {
		config_destroy(controller_procinfo->scenario);
	}
	if (controller_procinfo->config) {
		config_destroy(controller_procinfo->config);
	}
	buffer_manager_put(
	    controller_procinfo->controller->procinfo_buffer,
	    controller_procinfo);
}

static int
controller_alloc_procinfo(
	controller_t *controller,
	controller_procinfo_t **controller_procinfo)
{
	controller_procinfo_t *new;

	ASSERT(controller != NULL);
	ASSERT(controller_procinfo != NULL);
	if (buffer_manager_get(controller->procinfo_buffer, (void *)&new)) {
		return 1;
  	} 
	memset(new, 0, sizeof(controller_procinfo_t));
	new->controller_active = -1;
	new->socket = -1;
	new->controller = controller;
	*controller_procinfo = new;

	return 0;
}

static void
controller_free_procinfo_cb(
    void *args,
    void *data)
{
	controller_free_procinfo(data);
}

static int
controller_connect_target(
    int *sock,
    const char *addr,
    const char *port)
{
	int s = -1;
	struct addrinfo hints, *res, *res0 = NULL;
	int reuse_addr = 1;
	int nodelay = 1;
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

	ASSERT(sock != NULL);
	ASSERT(addr != NULL);
	ASSERT(port != NULL);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(addr, port, &hints, &res0) != 0) {
		logging(LOG_LV_ERR, "failed in getaddrinfo");
		goto last;
	}
	for (res = res0; res; res = res->ai_next) {
		if ((s = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
			logging(LOG_LV_WARNING, "failed in create socket");
			s = -1;
			continue;
		}
		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr))) {
			logging(LOG_LV_WARNING, "failed in set REUSEADDR");
			close(s);
			s = -1;
			continue;
		}
		if (setsockopt(s, SOL_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay))) {
			logging(LOG_LV_WARNING, "failed in set NODELAY");
			close(s);
			s = -1;
			continue;
		}
		if (getnameinfo(
		    res->ai_addr,
		    res->ai_addrlen,
		    hbuf, sizeof(hbuf),
		    sbuf, sizeof(sbuf),
		    NI_NUMERICHOST|NI_NUMERICSERV)) {
			logging(LOG_LV_NOTICE, "failed in getnameinfo %m");
		} else {
			logging(LOG_LV_INFO, "connect address = %s, port = %s", hbuf, sbuf);
		}
		if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
			logging(LOG_LV_WARNING, "failed in connect");
			close(s);
			s = -1;
			continue;
                }
		break;
	}
last:
	if (res0) {
		freeaddrinfo(res0);
	}
	if (s == -1) {
		return 1;
	}
	*sock = s;

	return 0;
}

static int
controller_script_execute(
    const char *script,
    const char *result,
    const char *request,
    const char *section,
    const char *lastcmd) {
	int error = 0;
	int st;
	char cmd_buffer[MAX_LINE_BUFFER * 4];

	ASSERT(script != NULL);
	ASSERT(request != NULL);
	ASSERT(section != NULL);
	ASSERT(lastcmd != NULL);
	snprintf(
	    cmd_buffer,
	    sizeof(cmd_buffer),
	    "%s %s %s %s '%s'",
	    script,
	    result,
	    request,
	    section,
	    lastcmd);
	logging(
	    LOG_LV_INFO,
	    "%s -c %s",
	    SHELL,
	    cmd_buffer);
	switch (fork()) {
	case -1:
		error = 1;
		break;
	case 0:
		/* 子側 */
		/* 子プロセスの管理はinitへ作戦 */
		switch (fork()) {
		case -1:
			error = EX_OSERR;
			break;
		case 0:
			/* 子側 */
			execl(
			    SHELL,
			    SHELL,
			    "-c",
			    cmd_buffer,
			    NULL);
			_exit(EX_OSERR);
			break;
		default:
			/* 親側 */
			error = EX_OK;
			break;
		}
		_exit(error);
		break;
	default:
		/* 親側 */
		/* 終了待ち */
		wait(&st);
		break;
	}

	return error;
}

static void
controller_replace_backword(
     char *target_buff,
     size_t target_buff_size,
     char *tmp_buff,
     size_t tmp_buff_size,
     controller_variable_t *variable)
{
	int i;
	int ret;

	ASSERT(target_buff != NULL);
	ASSERT(target_buff_size > 0);
	ASSERT(tmp_buff != NULL);
	ASSERT(tmp_buff_size > 0);
        ASSERT(variable != NULL);
	STRLCPY(target_buff, tmp_buff, target_buff_size);
	for (i = 0; i < MAX_MATCH; i++) {
		if (variable[i].name[0] == '\0' ||
		    variable[i].value[0] == '\0') {
			continue;
		}
		while (1) {
			 ret = string_replace(
			    target_buff,
			    target_buff_size,
			    tmp_buff,
			    variable[i].name,
			    variable[i].value);
			if (ret == -1) {
				logging(LOG_LV_WARNING,
				     "failed in backword replace %m");
				break;
			} else if (ret == 1) {
				break;
			}
			STRLCPY(
			    tmp_buff,
			    target_buff,
			    tmp_buff_size);
		}
	}
}

static void
controller_clear_all_event(
    controller_procinfo_t *controller_procinfo)
{
	if (evtimer_pending(
	    &controller_procinfo->cmd_arg.idle_timeout_event,
	    NULL)) {
		event_del(&controller_procinfo->cmd_arg.idle_timeout_event);
	}
	if (evtimer_pending(
	    &controller_procinfo->cmd_arg.periodic_event,
	    NULL)) {
		event_del(&controller_procinfo->cmd_arg.periodic_event);
	}
	if (event_pending(
	    &controller_procinfo->cmd_arg.read_event,
	    EV_READ,
	    NULL)) {
		event_del(&controller_procinfo->cmd_arg.read_event);
	}
	if (event_pending(
	    &controller_procinfo->cmd_arg.write_event,
	    EV_WRITE,
	    NULL)) {
		event_del(&controller_procinfo->cmd_arg.write_event);
	}

}

static void
controller_idle_timeout_cb(
    int sd,
    short event,
    void *arg)
{
	controller_procinfo_t *controller_procinfo = arg;

	ASSERT(arg != NULL);
	controller_procinfo->error = 1;
	controller_clear_all_event(controller_procinfo);
}

static void
controller_idle_timeout_refresh(
    controller_procinfo_t *controller_procinfo)
{
	/* idle timeoutイベント再登録 */
	if (evtimer_pending(
	    &controller_procinfo->cmd_arg.idle_timeout_event,
	    NULL)) {
		event_del(&controller_procinfo->cmd_arg.idle_timeout_event);
	}
	evtimer_set(
	     &controller_procinfo->cmd_arg.idle_timeout_event,
	     controller_idle_timeout_cb,
	     controller_procinfo);
        if (event_base_set(
            controller_procinfo->controller->event_base,
            &controller_procinfo->cmd_arg.idle_timeout_event)) {
                logging(LOG_LV_ERR, "failed in set event base %m");
		controller_procinfo->error = 1;
		controller_clear_all_event(controller_procinfo);
		return;
        }
	evtimer_add(
	    &controller_procinfo->cmd_arg.idle_timeout_event,
	    &controller_procinfo->cmd_arg.idle_timeout);
}

static void
controller_read_cb(
    int sd,
    short event,
    void *arg)
{
	controller_procinfo_t *controller_procinfo = arg;
	int rlen;
	regmatch_t pmatch[0];
	regex_t preg;
	int match;
	char *nl_ptr, *end_ptr;

	ASSERT(event == EV_READ);
	ASSERT(arg != NULL);
	controller_idle_timeout_refresh(controller_procinfo);
	rlen = read(
	    sd,
	    &controller_procinfo->cmd_arg.res_cmd_buff[
	    controller_procinfo->cmd_arg.res_cmd_buff_len],
	    sizeof(controller_procinfo->cmd_arg.res_cmd_buff) -
	    controller_procinfo->cmd_arg.res_cmd_buff_len);
	if (rlen <= 0) {
		if (rlen < 0) {
			logging(LOG_LV_NOTICE, "failed in read %m");
		} else {
			logging(LOG_LV_NOTICE, "closed by peer in read %m");
		}
		controller_procinfo->error = 1;
		controller_clear_all_event(controller_procinfo);
		return;
	}
	controller_procinfo->cmd_arg.res_cmd_buff_len += rlen;
	if (controller_procinfo->cmd_arg.res_cmd_buff_len >
	    sizeof(controller_procinfo->cmd_arg.res_cmd_buff) - 1) {
		logging(LOG_LV_NOTICE, "response is too long %m");
		controller_procinfo->error = 1;
		controller_clear_all_event(controller_procinfo);
		return;
	}
	controller_procinfo->cmd_arg.res_cmd_buff[
	    controller_procinfo->cmd_arg.res_cmd_buff_len] = '\0';
	if ((nl_ptr = strchr(controller_procinfo->cmd_arg.res_cmd_buff, '\n')) == NULL) {
		return;
	}
	if ((end_ptr = strstr(
	    controller_procinfo->cmd_arg.res_cmd_buff,
	    controller_procinfo->new_line)) != NULL) {
		*end_ptr = '\0';
	} else {
		*nl_ptr = '\0';
	}
	/* 次回の受信のために初期化しておく */
	controller_procinfo->cmd_arg.res_cmd_buff_len = 0;

	if (controller_procinfo->cmd_arg.expect_regex_buff[0] != '\0') {
		match = 0;
		if (regcomp(
		    &preg,
		    controller_procinfo->cmd_arg.expect_regex_buff,
		    REG_EXTENDED | REG_NOSUB)) {
			logging(LOG_LV_WARNING,
			     "failed in regex compile %s",
			     controller_procinfo->cmd_arg.expect_regex_buff);
			controller_procinfo->error = 1;
			controller_clear_all_event(controller_procinfo);
			return;
		}
		if (regexec(
		    &preg,
		    controller_procinfo->cmd_arg.res_cmd_buff,
		    0,
		    pmatch,
		    0) == 0) {
			match = 1;
		}
		regfree(&preg);
		if (match) {
			/* success expect */
			controller_clear_all_event(controller_procinfo);
			return;
		}
		logging(
		   LOG_LV_INFO,
		   "not match expect regex (%s)",
		   controller_procinfo->cmd_arg.res_cmd_buff);
                if (controller_procinfo->cmd_arg.res_regex_buff[0] == '\0') {
			controller_procinfo->error = 1;
			controller_clear_all_event(controller_procinfo);
			return;
		}
		if (regcomp(
		    &preg,
		    controller_procinfo->cmd_arg.res_regex_buff,
		    REG_EXTENDED | REG_NOSUB)) {
			logging(LOG_LV_WARNING,
			     "failed in regex compile %s", 
			    controller_procinfo->cmd_arg.res_regex_buff);
			controller_procinfo->error = 1;
			controller_clear_all_event(controller_procinfo);
			return;
		}
		if (regexec(
		    &preg,
		    controller_procinfo->cmd_arg.res_cmd_buff,
		    0,
		    pmatch,
		    0) == 0) {
			match = 1;
		}
		regfree(&preg);
		if (match) {
			/* success response */
			return;
		}
		/* not match */
		logging(
		    LOG_LV_INFO,
		    "not match response regex (%s)",
		    controller_procinfo->cmd_arg.res_cmd_buff);
		controller_procinfo->error = 1;
		controller_clear_all_event(controller_procinfo);
		return;
	} else {
		match = 0;
		if (regcomp(
		    &preg,
		    controller_procinfo->cmd_arg.res_regex_buff,
		    REG_EXTENDED | REG_NOSUB)) {
			logging(LOG_LV_WARNING,
			     "failed in regex compile %s", 
			    controller_procinfo->cmd_arg.res_regex_buff);
			controller_procinfo->error = 1;
			controller_clear_all_event(controller_procinfo);
			return;
		}
		if (regexec(
		    &preg,
		    controller_procinfo->cmd_arg.res_cmd_buff,
		    0,
		    pmatch,
		    0) == 0) {
			match = 1;
		}
		regfree(&preg);
		if (match) {
			/* success response */
			controller_clear_all_event(controller_procinfo);
			return;
		}
		/* not match */
		logging(
		    LOG_LV_INFO,
		    "not match response regex (%s)",
		    controller_procinfo->cmd_arg.res_cmd_buff);
		controller_procinfo->error = 1;
		controller_clear_all_event(controller_procinfo);
		return;
	}
}

static void
controller_write_cb(
    int sd,
    short event,
    void *arg)
{
	controller_procinfo_t *controller_procinfo = arg;
	int wlen;

	ASSERT(sd != -1);
	ASSERT(event == EV_WRITE);
	ASSERT(arg != NULL);
	controller_idle_timeout_refresh(controller_procinfo);
	wlen = write(
	    controller_procinfo->socket,
	    controller_procinfo->cmd_arg.req_cmd_buff,
	    controller_procinfo->cmd_arg.req_cmd_buff_len
	    - controller_procinfo->cmd_arg.req_cmd_write_len);
	if (wlen < 0) {
		logging(LOG_LV_NOTICE, "failed in write %m");
		controller_procinfo->error = 1;
		controller_clear_all_event(controller_procinfo);
		return;
	}
	controller_procinfo->cmd_arg.req_cmd_write_len += wlen;
	if (controller_procinfo->cmd_arg.req_cmd_write_len >=
	    controller_procinfo->cmd_arg.req_cmd_buff_len) {
		/* 次回の送信のために初期化しておく */
		controller_procinfo->cmd_arg.req_cmd_write_len = 0;
		/* レスポンスが何も無いならwriteして終了 */
		if (controller_procinfo->cmd_arg.expect_regex_buff[0] == '\0' &&
		    controller_procinfo->cmd_arg.res_regex_buff[0] == '\0') {
			controller_clear_all_event(controller_procinfo);
		}
		return;
	}
	/* writeイベント再登録 */
        event_set(
            &controller_procinfo->cmd_arg.write_event,
            controller_procinfo->socket,
            EV_WRITE,
            controller_write_cb,
            controller_procinfo);
        if (event_base_set(
            controller_procinfo->controller->event_base,
            &controller_procinfo->cmd_arg.write_event)){
                logging(LOG_LV_ERR, "failed in set event base %m");
		controller_procinfo->error = 1;
		controller_clear_all_event(controller_procinfo);
		return;
        }
        if (event_add(
	    &controller_procinfo->cmd_arg.write_event,
	    NULL)) {
                logging(LOG_LV_ERR, "failed in add liten event %m");
		controller_procinfo->error = 1;
		controller_clear_all_event(controller_procinfo);
		return;
        }
}
	
static void
controller_periodic_cb(
    int sd,
    short event,
    void *arg)
{
	controller_procinfo_t *controller_procinfo = arg;

	ASSERT(event == EV_TIMEOUT);
	ASSERT(arg != NULL);
	if (controller_procinfo->cmd_arg.req_cmd_buff[0] != '\0' &&
	    !event_pending(
	    &controller_procinfo->cmd_arg.write_event,
	    EV_WRITE,
	    NULL)) {
		event_set(
		    &controller_procinfo->cmd_arg.write_event,
		    controller_procinfo->socket,
		    EV_WRITE,
		    controller_write_cb,
		    controller_procinfo);
		if (event_base_set(
		    controller_procinfo->controller->event_base,
		    &controller_procinfo->cmd_arg.write_event)){
			logging(LOG_LV_ERR, "failed in set event base %m");
			controller_procinfo->error = 1;
			controller_clear_all_event(controller_procinfo);
			return;
		}
		if (event_add(
		    &controller_procinfo->cmd_arg.write_event,
		    NULL)) {
			logging(LOG_LV_ERR, "failed in add liten event %m");
			controller_procinfo->error = 1;
			controller_clear_all_event(controller_procinfo);
			return;
		}
	}
	if (controller_procinfo->cmd_arg.repeat_count > 0) {
		evtimer_set(
		     &controller_procinfo->cmd_arg.periodic_event,
		     controller_periodic_cb,
		     controller_procinfo);
		if (event_base_set(
		    controller_procinfo->controller->event_base,
		    &controller_procinfo->cmd_arg.periodic_event)){
			logging(LOG_LV_ERR, "failed in set event base %m");
			controller_procinfo->error = 1;
			controller_clear_all_event(controller_procinfo);
			return;
		}
		evtimer_add(
		    &controller_procinfo->cmd_arg.periodic_event,
		    &controller_procinfo->cmd_arg.periodic_interval);
		controller_procinfo->cmd_arg.repeat_count--;
	} else {
		if (controller_procinfo->cmd_arg.expect_regex_buff[0] != '\0') {
			logging(LOG_LV_NOTICE, "can not get expected response %m");
                        controller_procinfo->error = 1;
                        controller_clear_all_event(controller_procinfo);
                        return;
		}
	}
}


static int
controller_command(
    config_t *scenario,
    const char *section,
    void *arg)
{
	controller_procinfo_t *controller_procinfo = arg;
	int before_wait = DEFAULT_BEFORE_WAIT;
	int tmp_sec;
	char tmp_buff[(MAX_LINE_BUFFER * 2) + 2 /* new line */] = "";
	struct timeval initial_periodic_interval;
	
	ASSERT(section != NULL);
	ASSERT(arg != NULL);
	memset(
	    &controller_procinfo->cmd_arg,
	    0,
	    sizeof(controller_command_arg_t));
	timerclear(&initial_periodic_interval);

	/*
	 * 設定の取り出し
	 * まずは、idletimeout
	 */
	tmp_sec = DEFAULT_IDLE_TIMEOUT;
	if (config_get_int32(
    	    scenario,
	    &tmp_sec,
	    section,
	    CONF_KEY_IDLE_TIMEOUT,
	    DEFAULT_IDLE_TIMEOUT_STR,
	    MIN_IDLE_TIMEOUT,
	    MAX_IDLE_TIMEOUT)) {
		logging(LOG_LV_WARNING,
		     "failed in get idle timeout in %s section", section);
	}
	controller_procinfo->cmd_arg.idle_timeout.tv_sec = tmp_sec; 
	controller_procinfo->cmd_arg.idle_timeout.tv_usec = 0; 

	/* beforeWaitの取り出し */
	if (config_get_int32(
    	    scenario,
	    &before_wait,
	    section,
	    CONF_KEY_BEFORE_WAIT,
	    DEFAULT_BEFORE_WAIT_STR,
	    MIN_BEFORE_WAIT,
	    MAX_BEFORE_WAIT)) {
		logging(LOG_LV_WARNING,
		     "failed in get before wait in %s section", section);
	}

	/* periodicIntervalの取り出し */
	tmp_sec = DEFAULT_PERIODIC_INTERVAL;
	if (config_get_int32(
    	    scenario,
	    &tmp_sec,
	    section,
	    CONF_KEY_PERIODIC_INTERVAL,
	    DEFAULT_PERIODIC_INTERVAL_STR,
	    MIN_PERIODIC_INTERVAL,
	    MAX_PERIODIC_INTERVAL)) {
		logging(LOG_LV_WARNING,
		     "failed in get before wait in %s section", section);
	}
	controller_procinfo->cmd_arg.periodic_interval.tv_sec = tmp_sec;
	controller_procinfo->cmd_arg.periodic_interval.tv_usec = 0;

	/* repeatCountの取り出し */
	if (config_get_int32(
    	    scenario,
	    &controller_procinfo->cmd_arg.repeat_count,
	    section,
	    CONF_KEY_REPEAT_COUNT,
	    DEFAULT_REPEAT_COUNT_STR,
	    MIN_REPEAT_COUNT,
	    MAX_REPEAT_COUNT)) {
		logging(LOG_LV_WARNING,
		     "failed in get before wait in %s section", section);
	}

	/* requestCommandの取り出し */
	if (config_get_string(
    	    scenario,
	    tmp_buff,
	    sizeof(tmp_buff),
	    section,
	    CONF_KEY_REQUEST_COMMAND,
	    "",
	    sizeof(tmp_buff) - 1 - 2)) {
		logging(LOG_LV_WARNING,
		     "failed in get request line in %s section", section);
	}
	STRLCAT(
	    tmp_buff,
	    controller_procinfo->new_line, 
	    sizeof(tmp_buff));
	controller_replace_backword(
	     controller_procinfo->cmd_arg.req_cmd_buff,
	     sizeof(controller_procinfo->cmd_arg.req_cmd_buff),
	     tmp_buff,
	     sizeof(tmp_buff),
	     controller_procinfo->variable);
	controller_procinfo->cmd_arg.req_cmd_buff_len
	     = strlen(controller_procinfo->cmd_arg.req_cmd_buff);

	/* responseRegexの取り出し */
	if (config_get_string(
    	    scenario,
	    tmp_buff,
	    sizeof(tmp_buff),
	    section,
	    CONF_KEY_RESPONSE_REGEX,
	    "",
	    sizeof(tmp_buff) - 1)) {
		logging(LOG_LV_NOTICE,
		     "failed in get response regex in %s section", section);
	}
	controller_replace_backword(
	     controller_procinfo->cmd_arg.res_regex_buff,
	     sizeof(controller_procinfo->cmd_arg.res_regex_buff),
	     tmp_buff,
	     sizeof(tmp_buff),
	     controller_procinfo->variable);

	/* expectRegexの取り出し */
	if (config_get_string(
    	    scenario,
	    tmp_buff,
	    sizeof(tmp_buff),
	    section,
	    CONF_KEY_EXPECT_REGEX,
	    "",
	    sizeof(tmp_buff) - 1)) {
		logging(LOG_LV_NOTICE,
		     "failed in get expect regex in %s section", section);
	}
	controller_replace_backword(
	     controller_procinfo->cmd_arg.expect_regex_buff,
	     sizeof(controller_procinfo->cmd_arg.expect_regex_buff),
	     tmp_buff,
	     sizeof(tmp_buff),
	     controller_procinfo->variable);

	/* ignore errorフラグ取り出し */
	if (config_get_bool(
    	    scenario,
	    &controller_procinfo->cmd_arg.ignore_error,
	    section,
	    CONF_KEY_IGNORE_ERROR,
	    "false")) {
		logging(LOG_LV_NOTICE,
		     "failed in get ignore error in %s section", section);
	}

	/* 送信前にwaitする処理 */
	if (before_wait != 0) {
		sleep(before_wait);
	}

	/*
	 * 通信に関して:
	 *   1行のリクエストに対して、１行のレスポンスが
	 *   帰ってくることを想定している
	 */

	/* readイベント */
        event_set(
            &controller_procinfo->cmd_arg.read_event,
            controller_procinfo->socket,
            EV_READ | EV_PERSIST,
            controller_read_cb,
            controller_procinfo);
        if (event_base_set(
            controller_procinfo->controller->event_base,
            &controller_procinfo->cmd_arg.read_event)){
                logging(LOG_LV_ERR, "failed in set event base %m");
		if (controller_procinfo->cmd_arg.ignore_error) {
			return 0;
		} else {
			controller_procinfo->error = 1;
			return 1;
		}
        }
        if (event_add(
	    &controller_procinfo->cmd_arg.read_event,
	    NULL)) {
                logging(LOG_LV_ERR, "failed in add liten event %m");
		if (controller_procinfo->cmd_arg.ignore_error) {
			return 0;
		} else {
			controller_procinfo->error = 1;
			return 1;
		}
        }

	/* idle timeoutイベント */
	evtimer_set(
	     &controller_procinfo->cmd_arg.idle_timeout_event,
	     controller_idle_timeout_cb,
	     controller_procinfo);
        if (event_base_set(
            controller_procinfo->controller->event_base,
            &controller_procinfo->cmd_arg.idle_timeout_event)){
                logging(LOG_LV_ERR, "failed in set event base %m");
		if (controller_procinfo->cmd_arg.ignore_error) {
			return 0;
		} else {
			controller_procinfo->error = 1;
			return 1;
		}
        }
	evtimer_add(
	    &controller_procinfo->cmd_arg.idle_timeout_event,
	    &controller_procinfo->cmd_arg.idle_timeout);

	/* periodic event */
	evtimer_set(
	     &controller_procinfo->cmd_arg.periodic_event,
	     controller_periodic_cb,
	     controller_procinfo);
        if (event_base_set(
            controller_procinfo->controller->event_base,
            &controller_procinfo->cmd_arg.periodic_event)){
                logging(LOG_LV_ERR, "failed in set event base %m");
		if (controller_procinfo->cmd_arg.ignore_error) {
			return 0;
		} else {
			controller_procinfo->error = 1;
			return 1;
		}
        }
	evtimer_add(
	    &controller_procinfo->cmd_arg.periodic_event,
	    &initial_periodic_interval);

	/* イベントループへ */ 
	if (event_base_dispatch(
	    controller_procinfo->controller->event_base) == -1) {
                logging(LOG_LV_ERR, "failed in dispatch event %m");
		if (controller_procinfo->cmd_arg.ignore_error) {
			return 0;
		} else {
			controller_procinfo->error = 1;
			return 1;
		}
	}
	if (controller_procinfo->error) {
		if (controller_procinfo->cmd_arg.ignore_error) {
			controller_procinfo->error = 0;
			return 0;
		} else {
			return 1;
		}
	}

	return 0;
}

static void *
controller_main(
    void *arg)
{
	controller_t *controller = arg;
	const char *script_result;
	controller_procinfo_t *controller_procinfo;
	char tmp_exec_script[MAX_LINE_BUFFER];
	char *sp_ptr;

	ASSERT(arg != NULL);
	controller->event_base = event_init();
	if (controller->event_base  ==  NULL) {
		logging(LOG_LV_ERR, "failed in create event base");
		return NULL;
	}
	controller->main_run = 1;
	while (1) {
		if (!controller->main_run) {
			break;
		}
		/* queueを取り出す */
		if (queue_dequeue(
		    controller->queue,
		    (void *)&controller_procinfo,
		    NULL)) {
			logging(LOG_LV_ERR, "failed in dequeue");
			break;
		}
		if (controller_procinfo == NULL) {
			/* dequeue cancel でここに入る */
			continue;
		}

		/* ターゲットにつなぐ */
		if (controller_connect_target(
		    &controller_procinfo->socket,
		    controller_procinfo->connect_addr,
		    controller_procinfo->connect_port)) {
			logging(
			    LOG_LV_ERR,
			    "failed in connect target in %s", __func__);
			script_result = SCRIPT_RESULT_FAIL;
			goto last;
		}

		/* セクションを上から順にたどってコマンドを送る */
		if (config_section_foreach(
		    controller_procinfo->scenario,
		    controller_command,
		    controller_procinfo)) {
			logging(LOG_LV_ERR, "failed in section foreach");
			script_result = SCRIPT_RESULT_FAIL;
			goto last;
		}

		/* エラーチェックとスクリプト実行 */
		if (controller_procinfo->error) {
			script_result = SCRIPT_RESULT_FAIL;
		} else {
			script_result = SCRIPT_RESULT_SUCCESS;
		}

last:
		if (controller_procinfo->exec_script[0] != '\0') {
			STRLCPY(
			    tmp_exec_script,
			    controller_procinfo->exec_script,
			    sizeof(tmp_exec_script)); 
			sp_ptr = strchr(tmp_exec_script, ' ');
			if (sp_ptr) {
				*sp_ptr = '\0';
			}
			if (access(tmp_exec_script, R_OK | X_OK)) {
				logging(
				    LOG_LV_WARNING,
				    "can not access script file %s",
				    controller_procinfo->exec_script);
			} else {
				if (controller_script_execute(
				    controller_procinfo->exec_script,
				    script_result,
				    controller_procinfo->request,
				    controller_procinfo->section,
				    controller_procinfo->cmd_arg.req_cmd_buff)) {
					logging(
					    LOG_LV_ERR,
					    "failed in exec script %s",
					    controller_procinfo->exec_script);
				}
			}
		}
		controller_free_procinfo(controller_procinfo);
	}

	return NULL;
}

static int
controller_find_section(
    config_t *config,
    const char *section,
    void *arg)
{
	controller_procinfo_t *controller_procinfo = arg;
	char str[MAX_LINE_BUFFER];

	pcre* re;
	const char *regex_error;
	int regex_error_off;
	int ovector[(MAX_MATCH + 1) * 3];
	int rc;
	int request_len;
	int match_size;
	int match = 0;
	
	char varname_string[MAX_LINE_BUFFER];
	nsplit_t nsplit;
	int i;
	
	ASSERT(section != NULL);
	ASSERT(arg != NULL);
	request_len = strlen(controller_procinfo->request);
	if (strcmp(CONFIG_SECTION_GLOBAL_SETTING, section) == 0) {
		return 0;
	}
	/* 正規表現文字列取り出し */
	if (config_get_string(
    	    config,
	    str,
	    sizeof(str),
	    section,
	    CONF_KEY_MSG_REGEX,
	    NULL,
	    sizeof(str) - 1)) {
		logging(LOG_LV_WARNING,
		     "failed in get messageRegex in %s section", section);
		return 0;
	}

	/* 一致するか確認 */
	if ((re = pcre_compile(
	    str,
	    PCRE_UTF8,
	    &regex_error,
	    &regex_error_off,
	    NULL)) == NULL) {
		logging(LOG_LV_WARNING,
		    "failed in regex compilea (%s: %s)",
		    regex_error,
		    &str[regex_error_off]);
		return 0;
	}
        if ((rc = pcre_exec(
	    re,
	    NULL,
	    controller_procinfo->request,
	    request_len,
	    0,
	    0,
	    ovector,
	    sizeof(ovector)/sizeof(ovector[0]))) > 0) {
		match = 1;
	}

	/* 一致しない場合は次のセクションへ */
	if (!match) {
		pcre_free(re);
		return 0;
	}

	/*
	 *  後方参照変数の処理
	 *  pmatch[0]は全体なので無視する
	 */
	for (i = 0; i < MAX_MATCH && i < rc; i++) {
		snprintf(
		    controller_procinfo->variable[i].name,
		    sizeof(controller_procinfo->variable[i].name),
		    "$%d",
		    i);
		match_size = ovector[(i * 2) + 1] - ovector[i * 2] + 1 /* '\0' */;
		if (match_size > sizeof(controller_procinfo->variable[i].value)) {
		    logging(
		        LOG_LV_WARNING,
		        "matching backward is too long %s",
		        ovector[i * 2]);
			continue;
		}
		STRLCPY(
		    controller_procinfo->variable[i].value,
		    &controller_procinfo->request[ovector[i * 2]],
		    match_size);
	}
	pcre_free(re);

	/*
	 * 一致したのでその他の情報を取り出す処理
	 * まずセクション名をコピー
	 */
	STRLCPY(
	    controller_procinfo->section,
	    section,
	    sizeof(controller_procinfo->section));

	/* 後方参照用の変数名を変更する */
	config_get_string(
	    config,
	    varname_string,
	    sizeof(varname_string),
	    section,
	    CONF_KEY_VARIABLES_NAME,
	    "",
	    sizeof(varname_string) - 1);
	if (varname_string[0] != '\0') {
		if (string_nsplit_b(
		    &nsplit,
		    varname_string,
		    ",",
		    MAX_MATCH,
		    NULL)) {
			logging(
			    LOG_LV_WARNING,
			    "failed in split %s",
			    varname_string);
			nsplit.nelems = 0;
		}
		for (i = 0; i < nsplit.nelems && i < MAX_MATCH; i++) {
			if (nsplit.elems[i][0] == '\0') {
				continue;
			} 
			STRLCPY(
			    controller_procinfo->variable[i].name,
			    nsplit.elems[i],
			    sizeof(controller_procinfo->variable[i].name));
		}
	}

	/* コントローラーのアクティブ/非アクティブフラグ */
	config_get_bool(
	    config,
	    &controller_procinfo->controller_active,
	    section,
	    CONF_KEY_CNTRL_ACTIVE,
	    NULL);

	/* シナリオファイル */
	config_get_string(
	    config,
	    controller_procinfo->scenario_file,
	    sizeof(controller_procinfo->scenario_file),
	    section,
	    CONF_KEY_SCENARIO_FILE,
	    "",
	    sizeof(controller_procinfo->scenario_file) - 1);

	/* 接続先アドレス */
	config_get_address(
	    config,
	    controller_procinfo->connect_addr,
	    sizeof(controller_procinfo->connect_addr),
	    section,
	    CONF_KEY_CONNECT_ADDR,
	    NULL);

	/* 接続先ポート */
	config_get_port(
	    config,
	    controller_procinfo->connect_port,
	    sizeof(controller_procinfo->connect_port),
	    section,
	    CONF_KEY_CONNECT_PORT,
	    NULL);

	/* 実行スクリプト */
	config_get_string(
	    config,
	    controller_procinfo->exec_script,
	    sizeof(controller_procinfo->exec_script),
	    section,
	    CONF_KEY_EXECUTE_SCRIPT,
	    "",
	    sizeof(controller_procinfo->exec_script) - 1);

	/* 改行の種別 */
	config_get_string(
	    config,
	    str,
	    sizeof(str),
	    section,
	    CONF_KEY_NEW_LINE,
	    CONF_VALUE_NEW_LINE_CRLF,
	    CONF_VALUE_NEW_LINE_MAX);
	if (strcmp(str, CONF_VALUE_NEW_LINE_CRLF) == 0) {
		controller_procinfo->new_line = NEW_LINE_CRLF;
	} else if (strcmp(str, CONF_VALUE_NEW_LINE_LF) == 0) {
		controller_procinfo->new_line = NEW_LINE_LF;
	} else {
		controller_procinfo->new_line = NEW_LINE_CRLF;
	}

	return 1;
}

int
controller_create(
    controller_t **controller,
    const char *config_file)
{
	controller_t *new = NULL;
	char *copy_config_file = NULL;
	queue_t *new_queue = NULL;
	buffer_manager_t *new_buffer_manager = NULL;

	if (controller == NULL ||
	    config_file == NULL) {
		errno = EINVAL;
		return 1;
	}
	new = malloc(sizeof(controller_t));
	if (new == NULL) {
		goto fail;
	}
	memset(new, 0, sizeof(controller_t));
	copy_config_file = strdup(config_file);
	if (copy_config_file == NULL) {
		goto fail;
	}
	if (queue_create(
	    &new_queue,
    	    QUEUE_MODE_WAIT,
	    MAX_QUEUE_SIZE)) {
		goto fail;
	}
        if (buffer_manager_create(
            &new_buffer_manager,
            BUFFER_MANAGER_GLOW_OFF,
            sizeof(controller_procinfo_t),
            MAX_QUEUE_SIZE)) {
                goto fail;
        }
	new->config_file = copy_config_file;
	new->queue = new_queue;
	new->procinfo_buffer = new_buffer_manager;
	*controller = new;

	return 0;

fail:
	if (new_buffer_manager) {
		buffer_manager_destroy(new_buffer_manager);
	}
	if (new_queue) {
		queue_destroy(new_queue);
	}
	free(copy_config_file);
	free(new);

	return 1;
}

int
controller_destroy(
   controller_t *controller)
{
	if (controller == NULL) {
		return 1;
	}
	queue_destroy(controller->queue);
	buffer_manager_destroy(controller->procinfo_buffer);
	if (controller->event_base) {
		event_base_free(controller->event_base);
	}
	free(controller->config_file);
	free(controller);

	return 0;
}

int
controller_start(
    controller_t *controller)
{
	if (controller == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (pthread_create(
	   &controller->thread,
	   NULL,
	   controller_main,
	   controller)) {
		logging(LOG_LV_ERR, "failed in create thread");
		return 1;
	}

	return 0;
}

int
controller_stop(
    controller_t *controller)
{
	if (controller == NULL) {
		errno = EINVAL;
		return 1;
	}
	controller->main_run = 0;
	queue_dequeue_cancel(controller->queue, 1);
	pthread_join(controller->thread, NULL);

	return 0;
}

const char *
controller_enqueue(
    controller_t *controller,
    char *request)
{
	const char *result = RESULT_ACCEPT;
	controller_procinfo_t *new = NULL;
	const char *script_result = SCRIPT_RESULT_SUCCESS;
	int activity_change = 0;
	char tmp_exec_script[MAX_LINE_BUFFER];
	char *sp_ptr;

	/* キューに積む構造体を生成 */
	if (controller_alloc_procinfo(controller, &new)) {
		result = RESULT_BUSY;
		goto fail;
	}

	/* コンフィグをロードする */
	if (config_create(&new->config, controller->config_file)) {
		result = RESULT_INTERNAL_ERROR;
                logging(LOG_LV_ERR, "failed in create cofig in %s", __func__);
                goto fail;
        }
	if (config_load(new->config)) {
		result = RESULT_REJECT;
                logging(LOG_LV_ERR, "failed in load config in %s", __func__);
                goto fail;
        }

	/* 受け取ったrequestをコピーしておく */
	STRLCPY(new->request, request, sizeof(new->request));

	/*
         * 読み込んだコンフィグから該当するセクションを探る
         */
	if (config_section_foreach(
	    new->config,
	    controller_find_section,
	    new)) {
		logging(LOG_LV_ERR, "failed in section foreach");
		result = RESULT_INTERNAL_ERROR;
		goto fail;
	}

	/* 一致するセクションが無かったらreject */
	if (new->section[0] == '\0') {
		result = RESULT_REJECT;
		goto fail;
	}

	/* コントローラーのアクティブフラグ変更 */
	if (!controller->active && new->controller_active == 1) {
		logging(LOG_LV_INFO, "controller is active");
		controller->active = 1;	
		activity_change = 1;
	}  else if (controller->active && new->controller_active == 0) {
		logging(LOG_LV_INFO, "controller is inactive");
		controller->active = 0;	
		activity_change = 1;
	}
	if (!controller->active && !activity_change) {
		/* コントローラーがアクティブになってない */
		result = RESULT_NOT_READY;
		goto noenqueue;
	}

	/*
	 * 接続先が無いもしくはシナリオファイル指定が無い場合は
	 * ここで終わり
	 */
	if (new->connect_addr[0] == '\0' ||
	    new->connect_port[0] == '\0' ||
	    new->scenario_file[0] == '\0') {
		goto noenqueue;
	}

	/* シナリオファイルにアクセスできない場合はreject */
	if (access(new->scenario_file, R_OK)) {
		logging(LOG_LV_WARNING,
		    "can not access secnario file %s",
		    new->scenario_file);
		result = RESULT_REJECT;
		goto fail;
	}

	/* シナリオファイルを読み込む。失敗したらreject */
	if (config_create(&new->scenario, new->scenario_file)) {
		logging(LOG_LV_ERR, "failed in create scenario in %s", __func__);
		result = RESULT_INTERNAL_ERROR; 
		goto fail;	
	}
	if (config_load(new->scenario)) {
		logging(LOG_LV_ERR, "failed in load scenario in %s", __func__);
		result = RESULT_REJECT;
		goto fail;
	}

	/* キューに積む */
	if (queue_enqueue(
	    controller->queue,
	    new,
	    0,
	    controller_free_procinfo_cb,
	    NULL)) {
		logging(LOG_LV_ERR, "failed in enqueue");
		result = RESULT_INTERNAL_ERROR;
		goto fail;
	}

	return result;

fail:
	script_result = SCRIPT_RESULT_FAIL;
noenqueue:
	if (new != NULL) {
		if (strcmp(result, RESULT_ACCEPT) == 0 && 
		    new->exec_script[0] != '\0') {
			/* 引数は捨てる */
			STRLCPY(
			    tmp_exec_script,
			    new->exec_script,
			    sizeof(tmp_exec_script)); 
			sp_ptr = strchr(tmp_exec_script, ' ');
			if (sp_ptr) {
				*sp_ptr ='\0';
			}
			if (access(tmp_exec_script, R_OK | X_OK)) {
				logging(LOG_LV_WARNING,
				    "can not access script file %s",
				    new->exec_script);
			} else {
				if (controller_script_execute(
				    new->exec_script,
				    script_result,
				    new->request,
				    new->section,
				    new->cmd_arg.req_cmd_buff)) {
					logging(
					    LOG_LV_WARNING,
					    "failed in execute script %s",
					    new->exec_script);
				}
			}
		}
		controller_free_procinfo(new);
	}

	return result;
}
