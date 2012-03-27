#ifndef TCP_SOCK_H
#define TCP_SOCK_H

/* ソケット関連処理 */

typedef struct tcp_server tcp_server_t;

/* tcpサーバーを開始する             *
 * event_baseに対してeventを登録する *
 * この関数の後にevent_dispatch等を  *
 * 行う必要がある                    */
int tcp_server_start(
    tcp_server_t **tcp_server,
    controller_t *controller,
    struct event_base *event_base,
    const char *addr,
    const char *port);

/* tcpサーバーを止める */
int tcp_server_stop(
    tcp_server_t *tcp_server);

#endif
