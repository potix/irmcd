#include <sys/types.h>
#include <sys/param.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <event.h>
#include <netdb.h>

#include "debug.h"
#include "config.h"

#define SECTION "SETTING"
#ifndef DEFAULT_CONFIG_FILE
#define DEFAULT_CONFIG_FILE "./irmcd_notify.conf"
#endif

#define CONF_KEY_CONNECT_ADDR "connectAddr"
#define DEFAULT_CONNECT_ADDR "127.0.0.1"
#define CONF_KEY_CONNECT_PORT "connectPort"
#define DEFAULT_CONNECT_PORT "10023"
#define RES_BUFF_SIZE 2048

#define LOGGING_ARG(msg, ...) \
	printf("irmcd_notify: " msg, __VA_ARGS__)
#define LOGGING(msg, ...) \
	printf("irmcd_notify: " msg)

static int
connect_target(
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
		goto last;
	}
	for (res = res0; res; res = res->ai_next) {
		if ((s = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
			s = -1;
			continue;
		}
		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr))) {
			close(s);
			s = -1;
			continue;
		}
		if (setsockopt(s, SOL_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay))) {
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
		} else {
		}
		if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
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

int
get_plugin_info(
    int opcode,
    char *buf,
    int buflen)
{
	switch(opcode) {
	case 0:
		strncpy(buf, "irmcd notify plugin", buflen - 1);
		buf[buflen - 1] = '\0';
		break;
	}

	return 0;
}

void
result_best_str(
    char *result_str)
{
	const char *config_file;
	config_t *config = NULL;
	char connect_addr[CONFIG_MAX_STR_LEN];
	char connect_port[CONFIG_MAX_STR_LEN];
	int sock = -1;
	FILE *fp = NULL;
	char res_buff[RES_BUFF_SIZE];
	char *new_result_str;

	if (result_str == NULL) {
		return;
	}
	new_result_str = malloc(strlen(result_str) + 2);
	strcpy(new_result_str, result_str);
	strcat(new_result_str, "\n");
	config_file = getenv("IRMCD_NOTIFY_CONFIG_FILE");
	if (config_file == NULL) {
		config_file = DEFAULT_CONFIG_FILE;
	}
	LOGGING_ARG("config file = %s\n", config_file);
	if (config_create(&config, config_file)) {
		LOGGING("failed in create config\n");
		goto fail;
	}
	if (config_load(config)) {
		LOGGING("failed in load config\n");
		goto fail;
	}
        if (config_get_address(
            config,
            connect_addr,
            sizeof(connect_addr),
            SECTION,
            CONF_KEY_CONNECT_ADDR,
            DEFAULT_CONNECT_ADDR)) {
		LOGGING("failed in get address\n");
		goto fail;
	}
        if (config_get_port(
            config,
            connect_port,
            sizeof(connect_port),
            SECTION,
            CONF_KEY_CONNECT_PORT,
            DEFAULT_CONNECT_PORT)) {
		LOGGING("failed in get port\n");
		goto fail;
	}
	if (connect_target(
	    &sock,
	    connect_addr,
	    connect_port)) {
		LOGGING("failed in connect\n");
		goto fail;
	}
	printf("notify request: %s\n", new_result_str);
	int result_len = strlen(new_result_str);
	int write_len = 0;
	int wlen;
	while (write_len < result_len) {
		wlen = write(sock, &new_result_str[write_len], result_len - write_len);
		if (wlen < 0) {
			goto fail;
		}
		write_len += wlen;
	}
	fp = fdopen(sock, "r");
	if (fp == NULL) {
		LOGGING("failed in fdopen\n");
		goto fail;
	}
	while(fgets(res_buff, sizeof(res_buff), fp) != NULL) {
		printf("notify response: %s", res_buff);
		break;
	}
fail:
	if (config) {
		config_destroy(config);
	}
	if (fp) {
		fclose(fp);
	} else {
		if (sock != -1) {
			close(sock);
		}
	}
}
