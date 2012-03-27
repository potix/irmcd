#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <pthread.h>
#include <sys/param.h>
#include <semaphore.h>
#include <stdint.h>
#include <netdb.h>
#include <netinet/in.h>
#include <event.h>
#include <errno.h>


#include "debug.h"
#include "buffer_manager.h"
#include "queue.h"

struct queue_entry {
        long attribute;					/* attribute */
        void *data;					/* キューイングするデータポインタ */
        void (*free_cb)(void *free_args, void *data);	/* キューをfreeするcllback */
	void *free_args;				/* free時に渡す引数 */
        TAILQ_ENTRY(queue_entry) next;			/* 次のキューへの情報 */
};
typedef struct queue_entry queue_entry_t;

struct queue {
	TAILQ_HEAD(queue_head, queue_entry) queue_head;	/* queueのヘッド */
	buffer_manager_t *buffer_manager;	        /* thread buffer manager */
        int dequeue_cancel;				/* dequeue_cancelを識別する値 */
        int enqueue_cancel;				/* enqueue_cancelが識別する値 */
        int current_queue_size;				/* 現在のqueueのサイズ */
        int queue_full_count;				/* queueが一杯になった回数 */
        int buffer_put_fail_count;			/* buffeの返却に失敗した回数 */
        pthread_mutex_t lock;				/* queueのmutexロック */
	queue_mode_t mode;			        /* queueのモード */
        sem_t enqueue_sem;				/* enqueueをする際のセマフォ */
        sem_t dequeue_sem;				/* dequeueをする際のセマフォ */
};

int
queue_create(
    queue_t **queue,
    queue_mode_t mode,
    int max_queue_size)
{
	queue_t *new = NULL;
	buffer_manager_t *new_buffer_manager = NULL;

	if (queue == NULL ||
	    (mode != QUEUE_MODE_NOWAIT &&
	     mode != QUEUE_MODE_WAIT) ||
	    max_queue_size == 0) {
		errno = EINVAL;
		return 1;
	}
	new = malloc(sizeof(queue_t));
	if (new == NULL) {
		goto fail;
	}
	memset(new, 0, sizeof(queue_t));
	if (buffer_manager_create(
	    &new_buffer_manager,
	    BUFFER_MANAGER_GLOW_OFF,
	    sizeof(queue_entry_t),
	    max_queue_size)) {
		goto fail;
	}
	if (sem_init(&new->dequeue_sem, 0, 0) != 0) {
		goto fail;
	}
	if (sem_init(&new->enqueue_sem, 0, max_queue_size) != 0) {
		goto fail;
	}
	if (pthread_mutex_init(&new->lock, NULL) != 0) {
		goto fail;
	}
	TAILQ_INIT(&new->queue_head);
	new->buffer_manager = new_buffer_manager;
	new->mode = mode;
	*queue = new;

	return 0;

fail:
	if (new_buffer_manager) {
		buffer_manager_destroy(new_buffer_manager);
	}
	free(new);

	return 1;
}

int
queue_destroy(
    queue_t *queue)
{
	queue_entry_t *queue_entry, *queue_entry_next;

	if (queue == NULL) {
		errno = EINVAL;
		return 1;
	}
	queue_entry = TAILQ_FIRST(&queue->queue_head);
	while (queue_entry) {
		queue_entry_next = TAILQ_NEXT(queue_entry, next);
		TAILQ_REMOVE(&queue->queue_head, queue_entry, next);
		if (queue_entry->free_cb) {
			queue_entry->free_cb(queue_entry->free_args, queue_entry->data);
		}
		if (buffer_manager_put(
		    queue->buffer_manager,
		    (void *)queue_entry)) {
			queue->buffer_put_fail_count++;
		}
		queue_entry = queue_entry_next;
	}
	buffer_manager_destroy(queue->buffer_manager);
	pthread_mutex_destroy(&queue->lock);
	free(queue);

	return 0;
}

int
queue_enqueue(
    queue_t *queue,
    void *data,
    long attribute,
    void (*free_cb)(void *free_args, void *data),
    void *free_args)
{
	int error = 0;
	queue_entry_t *queue_entry;

	if (queue == NULL ||
	    data == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (queue->mode & QUEUE_MODE_WAIT) {
		/* enqueueできるまでwait */
retry:
		if (sem_wait(&queue->enqueue_sem)) {
			if (errno == EINTR) {
				goto retry;
			}
			ABORT("failed in wait semaphore (%m)");
			/* NOTREACHED */
		}
	}
        if (pthread_mutex_lock(&queue->lock) != 0) {
		ABORT("failed in lock");
		/* NOTREACHED */
        }
	/* bufferを取得 */
	if (buffer_manager_get(queue->buffer_manager, (void *)&queue_entry)) {
		if (errno == ENOBUFS) {
			if (queue->mode & QUEUE_MODE_WAIT) {
				if (queue->enqueue_cancel) {
					queue->enqueue_cancel -= 1;
				} else {
					ABORT("buffer is empty but requested enqueue");
					/* NOTREACHED */
				}
			} else {
				/* キューが一杯のときはカウント */
				queue->queue_full_count++;
				error = 1;
			}
			if (pthread_mutex_unlock(&queue->lock) != 0) {
				ABORT("failed in unlock");
				/* NOTREACHED */
			}
			return error;
		} else {
			ABORT("failed in get buffer");
			/* NOTREACHED */
		}
	} 
	/* バッファが確保できたのでenqueue */
	queue_entry->data = data;
	queue_entry->attribute = attribute;
	queue_entry->free_cb = free_cb;
	queue_entry->free_args = free_args;
	TAILQ_INSERT_TAIL(&queue->queue_head, queue_entry, next);
	queue->current_queue_size++;
        if (pthread_mutex_unlock(&queue->lock) != 0) {
		ABORT("failed in unlock");
		/* NOTREACHED */
        }
	if (queue->mode & QUEUE_MODE_WAIT) {
		/* dequeueできる個数を1増やす */
		if (sem_post(&queue->dequeue_sem)) {
			ABORT("failed in post semaphore");
		}
	}

	return 0;
}

int
queue_dequeue(
    queue_t *queue,
    void **data,
    long *attribute)
{
	int error = 0;
	queue_entry_t *queue_entry;

	if (queue == NULL ||
	    data == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (queue->mode & QUEUE_MODE_WAIT) {
		/* dequeueできるまでwait */
retry:
		if (sem_wait(&queue->dequeue_sem)) {
			if (errno == EINTR) {
				goto retry;
			}
			ABORT("failed in wait semaphore (%m)");
			/* NOTREACHED */
		}
	}
        if (pthread_mutex_lock(&queue->lock) != 0) {
		ABORT("failed in lock");
		/* NOTREACHED */
        }
	queue_entry = TAILQ_FIRST(&queue->queue_head);
	if (queue_entry == NULL) {
		if (queue->mode & QUEUE_MODE_WAIT) {
			if (queue->dequeue_cancel) {
				queue->dequeue_cancel -= 1;
			} else {
				ABORT("queue is empty but requested dequeue");
				/* NOTREACHED */
			}
		} else {
			error = 1;
		}
		*data = NULL;
		if (pthread_mutex_unlock(&queue->lock) != 0) {
			ABORT("failed in unlock");
			/* NOTREACHED */
		}
		return error;
        }
	TAILQ_REMOVE(&queue->queue_head, queue_entry, next);
	queue->current_queue_size--;
	if (attribute) {
		*attribute = queue_entry->attribute;
	}
	*data = queue_entry->data;
	if (buffer_manager_put(
	    queue->buffer_manager,
	    queue_entry)) {
		ABORT("failed in put buffer");
		/* NOTREACHED */
	}
        if (pthread_mutex_unlock(&queue->lock) != 0) {
		ABORT("failed in unlock");
		/* NOTREACHED */
        }
	if (queue->mode & QUEUE_MODE_WAIT) {
		/* enqueueできる個数を1増やす */
		if (sem_post(&queue->enqueue_sem)) {
			ABORT("failed in post semaphore");
			/* NOTREACHED */
		}
	}

	return 0;
}

int
queue_enqueue_cancel(
    queue_t *queue,
    int cancel_count)
{
	int i;

	if (queue == NULL ||
	    cancel_count <= 0) {
		errno = EINVAL;
		return 1;
	}
	if (!(queue->mode & QUEUE_MODE_WAIT)) {
		return 0;
	}
        if (pthread_mutex_lock(&queue->lock) != 0) {
		ABORT("failed in lock");
		/* NOTREACHED */
        }
	queue->enqueue_cancel += cancel_count;
        if (pthread_mutex_unlock(&queue->lock) != 0) {
		ABORT("failed in unlock");
		/* NOTREACHED */
        }
	for (i = 0; i < cancel_count; i++) {
		sem_post(&queue->enqueue_sem);
	}

	return 0;
}

int
queue_dequeue_cancel(
    queue_t *queue,
    int cancel_count)
{
	int i;

	if (queue == NULL ||
	    cancel_count <= 0) {
		errno = EINVAL;
		return 1;
	}
        if (pthread_mutex_lock(&queue->lock) != 0) {
		ABORT("failed in lock");
		/* NOTREACHED */
        }
	queue->dequeue_cancel += cancel_count;
        if (pthread_mutex_unlock(&queue->lock) != 0) {
		ABORT("failed in unlock");
		/* NOTREACHED */
        }
	for (i = 0; i < cancel_count; i++) {
		sem_post(&queue->dequeue_sem);
	}

	return 0;
}

int
queue_get_statistics(
    queue_t *queue,
    int *queue_count,
    int *queue_full_count,
    int *buffer_put_fail_count)
{
	if (queue == NULL) {
		errno = EINVAL;
		return 1;
	}
        if (pthread_mutex_lock(&queue->lock) != 0) {
		ABORT("failed in lock");
		/* NOTREACHED */
        }
	if (queue_count) {
		*queue_count = queue->current_queue_size;
	}
	if (queue_full_count) {
		*queue_full_count = queue->queue_full_count;
	}
	if (buffer_put_fail_count) {
		*buffer_put_fail_count = queue->buffer_put_fail_count;
	}
        if (pthread_mutex_unlock(&queue->lock) != 0) {
		ABORT("failed in unlock");
		/* NOTREACHED */
        }

	return 0;
}
