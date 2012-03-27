#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <event.h>

#include "debug.h"
#include "logger.h"
#include "controller.h"
#include "tcp_sock.h"
#include "config.h"

#ifndef MAX_TCP_LISTEN
#define MAX_TCP_LISTEN 8
#endif
#ifndef READ_TIMEOUT
#define READ_TIMEOUT 10
#endif
#ifndef WRITE_TIMEOUT
#define WRITE_TIMEOUT 10
#endif
#define MAX_LINE_BUFFER CONFIG_LINE_BUF

#define READ_EVENT 0x01
#define WRITE_EVENT 0x02

typedef struct tcp_listen tcp_listen_t;
typedef struct tcp_client tcp_client_t;
typedef struct tcp_client_response tcp_client_response_t;

struct tcp_client_response {
	char result[MAX_LINE_BUFFER];
	int result_len;
	int write_len;
	TAILQ_ENTRY(tcp_client_response) next;
};

struct tcp_client {
	int sd;
	struct event read_event;
	struct event write_event;
        union {
                struct sockaddr_in in;
                struct sockaddr_in6 in6;
        } remote;
        socklen_t remote_len;
	char recvbuffer[MAX_LINE_BUFFER];
	int recvbuffer_len;
	TAILQ_HEAD(response_head, tcp_client_response) response_head;
	tcp_listen_t *tcp_listen;
	LIST_ENTRY(tcp_client) next;
};

struct tcp_listen {
	int sd;
	struct event read_event;
	LIST_HEAD(tcp_client_head, tcp_client) client_head;
	tcp_server_t *tcp_server;
};

struct tcp_server {
	struct event_base *event_base;
	controller_t *controller;
	tcp_listen_t tcp_listen[MAX_TCP_LISTEN];
	int tcp_listen_count;
};

static void tcp_server_on_send(
    int fd,
    short event,
    void *arg);

static void tcp_server_on_recv(
    int fd,
    short event,
    void *arg);

static void
set_nonblocking(
    int sd)
{
	int fd_flags;

	ASSERT(sd != -1);
	if ((fd_flags = fcntl(sd, F_GETFL, 0)) < 0) {
		logging(LOG_LV_ERR, "failed in get current fd flags %m");
	} else {
		if (fcntl(sd, F_SETFL, fd_flags | O_NONBLOCK) < 0) {
			logging(LOG_LV_ERR, "failed in set nonblocking flag %m");
		}
	}
}

static void
tcp_server_client_finish(
    tcp_client_t *tcp_client)
{
	tcp_client_response_t *tcp_client_response, *tcp_client_response_next;

	ASSERT(tcp_client != NULL);
	LIST_REMOVE(tcp_client, next);
	tcp_client_response = TAILQ_FIRST(&tcp_client->response_head);
	while(tcp_client_response) {
		tcp_client_response_next = TAILQ_NEXT(tcp_client_response, next);
		TAILQ_REMOVE(&tcp_client->response_head, tcp_client_response, next);
		free(tcp_client_response);
		tcp_client_response = tcp_client_response_next;				
	}
	if (event_pending(&tcp_client->read_event, EV_READ | EV_TIMEOUT, NULL)) {
		logging(LOG_LV_INFO, "delete read event %m");
		event_del(&tcp_client->read_event);
	}
	if (event_pending(&tcp_client->write_event, EV_WRITE | EV_TIMEOUT, NULL)) {
		logging(LOG_LV_INFO, "delete write event %m");
		event_del(&tcp_client->write_event);
	}
	close(tcp_client->sd);
	free(tcp_client);
}

static void
tcp_server_reset_write_event(
    tcp_listen_t *tcp_listen,
    tcp_client_t *tcp_client)
{
	struct timeval write_timeout;

	ASSERT(tcp_listen != NULL);
	ASSERT(tcp_client != NULL);
	write_timeout.tv_sec = WRITE_TIMEOUT;
	write_timeout.tv_usec = 0;
	event_set(
	    &tcp_client->write_event,
	    tcp_client->sd,
	    EV_WRITE | EV_TIMEOUT,
	    tcp_server_on_send,
	    tcp_client);
	if (event_base_set(
	    tcp_listen->tcp_server->event_base,
	    &tcp_client->write_event)){
		logging(LOG_LV_ERR, "failed in set event base %m");
		tcp_server_client_finish(tcp_client);
		return;
	}
	if (event_add(&tcp_client->write_event, &write_timeout)) {
		logging(LOG_LV_ERR, "failed in add liten event %m");
		tcp_server_client_finish(tcp_client);
		return;
	}
	return;
}

static void
tcp_server_on_send(
    int fd,
    short event,
    void *arg)
{
	tcp_client_t *tcp_client = arg;
	tcp_listen_t *tcp_listen;
	tcp_client_response_t *tcp_client_response;
	int write_len;

	ASSERT((event == EV_WRITE || event == EV_TIMEOUT));
	ASSERT(arg != NULL);
	tcp_listen = tcp_client->tcp_listen;
	if (event == EV_TIMEOUT) {
		logging(LOG_LV_INFO, "write timeout in %s", __func__);
		tcp_server_client_finish(tcp_client);
		return;
	}
	tcp_client_response = TAILQ_FIRST(&tcp_client->response_head);
	if (!tcp_client_response) {
		return;
	}
	write_len = write(
	    tcp_client->sd,
	    &tcp_client_response->result[tcp_client_response->write_len],
	    tcp_client_response->result_len - tcp_client_response->write_len);
	if (write_len == 0) {
		logging(LOG_LV_INFO, "closed by peer (%m) in %s", __func__);
		tcp_server_client_finish(tcp_client);
		return;
	} else if (write_len < 0) {
		if (errno == EAGAIN) {
			tcp_server_reset_write_event(tcp_listen, tcp_client);
			return;
		}
		logging(LOG_LV_ERR, "failed in write (%m) in %s", __func__);
		tcp_server_client_finish(tcp_client);
		return;
	}
	tcp_client_response->write_len += write_len;
	if (write_len >= tcp_client_response->result_len) {
		TAILQ_REMOVE(
		   &tcp_client->response_head,
		   tcp_client_response,
		   next);
		free(tcp_client_response);
		if (!TAILQ_EMPTY(&tcp_client->response_head)) {
			/* まだレスポンスデータがあるので一度WRITEする */
			tcp_server_reset_write_event(tcp_listen, tcp_client);
			return;
		}
	} else {
		/* まだ完全に書き込めてないのでもう一度WRITEする */
		tcp_server_reset_write_event(tcp_listen, tcp_client);
		return;
	}

	return;
}

static void
tcp_server_reset_read_event(
    tcp_listen_t *tcp_listen,
    tcp_client_t *tcp_client)
{
	struct timeval read_timeout;

	ASSERT(tcp_listen != NULL);
	ASSERT(tcp_client != NULL);
	read_timeout.tv_sec = READ_TIMEOUT;
	read_timeout.tv_usec = 0;
	event_set(
	    &tcp_client->read_event,
	    tcp_client->sd,
	    EV_READ | EV_TIMEOUT,
	    tcp_server_on_recv,
	    tcp_client);
	if (event_base_set(
	    tcp_listen->tcp_server->event_base,
	    &tcp_client->read_event)){
		logging(LOG_LV_ERR, "failed in set event base %m");
		tcp_server_client_finish(tcp_client);
		return;
	}
	if (event_add(&tcp_client->read_event, &read_timeout)) {
		logging(LOG_LV_ERR, "failed in add liten event %m");
		tcp_server_client_finish(tcp_client);
		return;
	}

	return;	
}

static void
tcp_server_on_recv(
    int fd,
    short event,
    void *arg)
{
	tcp_client_t *tcp_client = arg;
	tcp_listen_t *tcp_listen;
	controller_t *controller;
	tcp_client_response_t *tcp_client_response;
	int read_len;
	struct timeval write_timeout;
	char *line_ptr, *newline_ptr, *cr_ptr;
	int line_len;
	const char *result;

	ASSERT(arg != NULL);
	ASSERT((event == EV_READ || event == EV_TIMEOUT));
	if (event == EV_TIMEOUT) {
		logging(LOG_LV_INFO, "read timeout in %s", __func__);
		tcp_server_client_finish(tcp_client);
		return;
	}
	write_timeout.tv_sec = WRITE_TIMEOUT;
	write_timeout.tv_usec = 0;
	tcp_listen = tcp_client->tcp_listen;
	controller = tcp_listen->tcp_server->controller;
	read_len = read(
	    tcp_client->sd,
	    &tcp_client->recvbuffer[tcp_client->recvbuffer_len],
	    sizeof(tcp_client->recvbuffer) - tcp_client->recvbuffer_len);
	if (read_len == 0) {
		logging(LOG_LV_INFO, "closed by peer (%m) in %s", __func__);
		tcp_server_client_finish(tcp_client);
		return;
	} else if (read_len < 0) {
		if (errno == EAGAIN) {
			tcp_server_reset_read_event(tcp_listen, tcp_client);
			return;	
		}
		logging(LOG_LV_ERR, "failed in read (%m) in %s", __func__);
		tcp_server_client_finish(tcp_client);
		return;
	}

	/* リクエストがでかすぎるばあいは切断 */
	tcp_client->recvbuffer_len += read_len;
	if (tcp_client->recvbuffer_len > sizeof(tcp_client->recvbuffer) - 1) {
		logging(LOG_LV_ERR, "too long request (%m) in %s", __func__);
		tcp_server_client_finish(tcp_client);
		return;
	}

	/* まだ改行がない場合は、もう一度readする */
	newline_ptr = strchr(tcp_client->recvbuffer, '\n');
	if (newline_ptr == NULL) {
		tcp_server_reset_read_event(tcp_listen, tcp_client);
		return;	
	}

	/* レスポンスデータ領域の作成 */
	tcp_client_response = malloc(sizeof(tcp_client_response_t));
	if (tcp_client_response == NULL) {
		logging(LOG_LV_ERR, "failed in allocate (%m) %s", __func__);
		tcp_server_client_finish(tcp_client);
		return;
	}
	TAILQ_INSERT_TAIL(&tcp_client->response_head, tcp_client_response, next);

	/* １行分取り出す */
	*newline_ptr = '\0';
	line_ptr = &tcp_client->recvbuffer[0];
	line_len = newline_ptr + 1 - &tcp_client->recvbuffer[0];
	if ((cr_ptr = strchr(line_ptr, '\r')) != NULL) {
		*cr_ptr = '\0';
	}
	
	/* controllerキューに積んでに処理を渡す */
	result = controller_enqueue(controller, line_ptr);
	tcp_client_response->result_len = snprintf(
	    tcp_client_response->result,
	    sizeof(tcp_client_response->result),
	    "%s\n",
	    result); 
	tcp_client_response->write_len = 0;

	/* 取り出した分を前につめる */
	memmove(line_ptr, newline_ptr + 1, tcp_client->recvbuffer_len - line_len);
	tcp_client->recvbuffer_len -= line_len;

	/* レスポンス用の書き込みイベントを登録 */
	if (!event_pending(&tcp_client->write_event, EV_WRITE, NULL)) {
		event_set(
		    &tcp_client->write_event,
		    tcp_client->sd,
		    EV_WRITE | EV_TIMEOUT,
		    tcp_server_on_send, tcp_client);
		if (event_base_set(
		    tcp_listen->tcp_server->event_base,
		    &tcp_client->write_event)){
			logging(LOG_LV_ERR, "failed in set event base %m");
			TAILQ_REMOVE(
			    &tcp_client->response_head,
			    tcp_client_response,
			    next);
			free(tcp_client_response);
			tcp_server_client_finish(tcp_client);
			return;
		}
		if (event_add(&tcp_client->write_event, &write_timeout)) {
			logging(LOG_LV_ERR, "failed in add liten event %m");
			TAILQ_REMOVE(
			    &tcp_client->response_head,
			    tcp_client_response,
			    next);
			free(tcp_client_response);
			tcp_server_client_finish(tcp_client);
			return;
		}
	}

	/* 次のREADイベントを登録 */
	tcp_server_reset_read_event(tcp_listen, tcp_client);

	return;
}

static void
tcp_server_on_connect(
    int fd,
    short event,
    void *arg)
{
	tcp_listen_t *tcp_listen = arg;
	tcp_client_t *tcp_client = NULL;
	struct timeval read_timeout;
	read_timeout.tv_sec = READ_TIMEOUT;
	read_timeout.tv_usec = 0;

	ASSERT(fd != -1);
	ASSERT(arg != NULL);
	ASSERT((event == EV_READ));
	tcp_client = malloc(sizeof(tcp_client_t));
	if (tcp_client == NULL) {
		logging(LOG_LV_ERR, "failed in allocate client struct %m");	
		return;
	}
	memset(tcp_client, 0, sizeof(tcp_client_t));
	TAILQ_INIT(&tcp_client->response_head);
	tcp_client->remote_len = sizeof(tcp_client->remote);
	tcp_client->tcp_listen = tcp_listen;
        if ((tcp_client->sd = accept(
	    tcp_listen->sd,
	    (struct sockaddr *)&tcp_client->remote,
	    &tcp_client->remote_len)) < 0) {
		goto fail;
        }
	set_nonblocking(tcp_client->sd);
	event_set(
	    &tcp_client->read_event,
	    tcp_client->sd,
	    EV_READ | EV_TIMEOUT,
	    tcp_server_on_recv, tcp_client);
	if (event_base_set(
	    tcp_listen->tcp_server->event_base,
	    &tcp_client->read_event)){
		logging(LOG_LV_ERR, "failed in set event base %m");
		goto fail;
	}
	if (event_add(&tcp_client->read_event, &read_timeout)) {
		logging(LOG_LV_ERR, "failed in add liten event %m");
		goto fail;
	}
	LIST_INSERT_HEAD(&tcp_listen->client_head, tcp_client, next);

	return;

fail:
	free(tcp_client);
}

int
tcp_server_start(
    tcp_server_t **tcp_server,
    controller_t *controller,
    struct event_base *event_base,
    const char *addr,
    const char *port)
{
	tcp_server_t *new = NULL;	
	tcp_listen_t *tcp_listen;	
	const char *l_addr;
        struct addrinfo hints, *res, *res0 = NULL;
        int sd = -1;
        int v6only = 1;
        int reuse_addr = 1;
        int nodelay = 1;
	int i;
	char hbuf[NI_MAXHOST];
	char sbuf[NI_MAXSERV];

	if (tcp_server == NULL || port == NULL || *port == '\0') {
		errno = EINVAL;
		return 1;
	}
	if (*addr == '\0') {
		l_addr = NULL;
	} else {
		l_addr = addr;
	}
	new = malloc(sizeof(tcp_server_t));
	if (new == NULL) {
		goto fail;
	}
	memset(new, 0 , sizeof(tcp_server_t));
	for (i = 0 ; i < sizeof(new->tcp_listen)/sizeof(new->tcp_listen[0]); i++) {
		LIST_INIT(&new->tcp_listen[i].client_head);
		new->tcp_listen[i].sd = -1;
	}
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = PF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        if (getaddrinfo(l_addr, port, &hints, &res0) != 0) {
                logging(LOG_LV_ERR, "failed in getaddrinfo %m");
                goto fail;
        }
	for (res = res0;
	     new->tcp_listen_count < sizeof(new->tcp_listen)/sizeof(new->tcp_listen[0]) && res;
	     res = res->ai_next) {
		if ((sd = socket(
		    res->ai_family,
		    res->ai_socktype,
		    res->ai_protocol)) < 0) {
			logging(LOG_LV_ERR, "failed in socket %m");
			continue;
		}
		set_nonblocking(sd);
		if (res->ai_family == AF_INET6) {
			if (setsockopt(
			    sd,
			    IPPROTO_IPV6,
			    IPV6_V6ONLY,
			    &v6only,
			    sizeof(v6only))) {
				logging(LOG_LV_ERR, "failed in setsockopt %m");
				continue;
			}
		}
		if (setsockopt(
		    sd,
		    SOL_SOCKET,
		    SO_REUSEADDR,
		    &reuse_addr,
		    sizeof(reuse_addr))) {
			logging(LOG_LV_ERR, "failed in setsockopt %m");
			continue;
		}
		if (setsockopt(
		    sd,
		    SOL_TCP,
		    TCP_NODELAY,
		    &nodelay,
		    sizeof(nodelay))) {
			logging(LOG_LV_ERR, "failed in setsockopt %m");
			continue;
		}
		if (bind(sd, res->ai_addr, res->ai_addrlen) < 0) {
			logging(LOG_LV_ERR, "failed in bind %m");
		       continue;
		}
		if (listen(sd, 0) < 0) {
			logging(LOG_LV_ERR, "failed in listen %m");
			continue;
		}
		if (getnameinfo(
		     res->ai_addr,
		     res->ai_addrlen,
		     hbuf, sizeof(hbuf),
		     sbuf, sizeof(sbuf),
		     NI_NUMERICHOST|NI_NUMERICSERV)) {
			logging(LOG_LV_ERR, "failed in getnameinfo %m");
		} else {
			logging(
			    LOG_LV_INFO,
			    "tcp server listen: address = %s, port = %s",
			    hbuf,
			    sbuf);
		}
		tcp_listen = &new->tcp_listen[new->tcp_listen_count];
		new->tcp_listen_count++;
		tcp_listen->sd = sd;
		tcp_listen->tcp_server = new;
		event_set(
		    &tcp_listen->read_event,
		    sd, EV_READ | EV_PERSIST,
		    tcp_server_on_connect,
		    tcp_listen);
		if (event_base_set(event_base, &tcp_listen->read_event)){
			logging(LOG_LV_ERR, "failed in set event base %m");
			goto fail;
		}
		if (event_add(&tcp_listen->read_event, NULL)) {
			logging(LOG_LV_ERR, "failed in add liten event %m");
			goto fail;
		}
	}
	if (new->tcp_listen_count == 0) {
		logging(LOG_LV_ERR, "no listen socket");
		goto fail;
	}
	freeaddrinfo(res0);
	new->controller = controller;
	new->event_base = event_base;
	*tcp_server = new;

	return 0;

fail:
	if (res0 != NULL)
		freeaddrinfo(res0);
	for (i = 0; i < new->tcp_listen_count; i++) {
		if (new->tcp_listen[i].sd != -1)
			close(new->tcp_listen[i].sd);
	}
	free(new);

	return 1;
}

int
tcp_server_stop(
    tcp_server_t *tcp_server)
{
	int i;
	tcp_client_t *tcp_client, *tcp_client_next;
	tcp_client_response_t *tcp_client_response, *tcp_client_response_next;

	if (tcp_server == NULL) {
		errno = EINVAL;
		return 1;
	}
	for (i = 0; i < tcp_server->tcp_listen_count; i++) {
		tcp_client = LIST_FIRST(&tcp_server->tcp_listen[i].client_head);
		while (tcp_client) {
			tcp_client_next = LIST_NEXT(tcp_client, next);
			LIST_REMOVE(tcp_client, next);
			tcp_client_response =
			    TAILQ_FIRST(&tcp_client->response_head);
			while(tcp_client_response) {
				tcp_client_response_next =
				     TAILQ_NEXT(tcp_client_response, next);
				TAILQ_REMOVE(
				    &tcp_client->response_head,
				    tcp_client_response,
				    next);
				free(tcp_client_response);
				tcp_client_response = tcp_client_response_next;	
			}
			if (event_pending(
			    &tcp_client->read_event,
			    EV_READ | EV_TIMEOUT,
			    NULL)) {
				event_del(&tcp_client->read_event);
			}
			if (event_pending(
			    &tcp_client->write_event,
			    EV_WRITE | EV_TIMEOUT,
			    NULL)) {
				event_del(&tcp_client->write_event);
			}
			close(tcp_client->sd);
			free(tcp_client);
			tcp_client = tcp_client_next;
		}
		event_del(&tcp_server->tcp_listen[i].read_event);
		close(tcp_server->tcp_listen[i].sd);
	}
	free(tcp_server);

	return 0;
}

