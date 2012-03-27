#ifndef QUEUE_H
#define QUEUE_H

/*
 *    threadでのキューの管理。
 *    enqueueで詰め込み、dequeueで取り出す。
 *    QUEUE_MODE_WAITをするとqueueがfullのときのenqueueと
 *    queueが空のときのdequeueでブロックする
 *    block状態をを抜けるには、dequeue_cancelを呼ぶ必要がある。
 *    enqueueをcancelすると1がかえり、dequeueをキャンセルするとNULLがかえる
 *    QUEUE_MODE_NOWAITのときqueue fullが発生したら1をかえす
 *    queueがない状態でdequeueをするとNULLがかえる
 */

enum queue_mode {
	QUEUE_MODE_NOWAIT = 1,
	QUEUE_MODE_WAIT,
};
typedef enum queue_mode queue_mode_t;
typedef struct queue queue_t;

/*
 * queueコンテキストの作成
 */
int
queue_create(
    queue_t **queue,
    queue_mode_t mode,
    int max_queue_size);

/*
 * queueコンテキストの削除
 */
int queue_destroy(
    queue_t *queue);

/*
 * queueに積む
 */
int queue_enqueue(
    queue_t *queue,
    void *data,
    long attribute,
    void (*free_cb)(void *free_args, void *data),
    void *free_args);

/*
 * queueから取り出し
 */
int queue_dequeue(
    queue_t *queue,
    void **data,
    long *attribute);

/*
 * ブロッキングしているenqueueをキャンセルする
 */
int queue_enqueue_cancel(
    queue_t *queue,
    int cancel_count);

/*
 * ブロッキングしているdequeueをキャンセルする
 */
int queue_dequeue_cancel(
    queue_t *queue,
    int cancel_count);

/*
 * statictics情報を返す
 * 主にdebug用途
 */
int queue_get_statistics(
    queue_t *queue,
    int *queue_count,
    int *queue_full_count,
    int *buffer_put_fail_count);

#endif
