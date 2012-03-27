#include <sys/queue.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>

#include "debug.h"
#include "buffer_manager.h"

#define VERIFY_MAGIC 0xDEADBEEFBABECAFEULL

struct alloc_ptr {
	TAILQ_ENTRY(alloc_ptr) next;
	uint64_t padding;
	/* (sizeof(buffer_t) + buffer_size) * unit_count */ 
};
typedef struct alloc_ptr alloc_ptr_t;

struct buffer {
	TAILQ_ENTRY(buffer) next;
	uint64_t padding; 
	/* buffer_size */
};
typedef struct buffer buffer_t;

struct buffer_manager {
	/* bufferの拡張をするかどうか */
	int glow;

	/* allocしたバッファの先頭ポインタのリスト */
	TAILQ_HEAD(alloc_ptr_head, alloc_ptr) alloc_ptr_head;

	/* 空きバッファのリスト */
	TAILQ_HEAD(free_buffer_head, buffer) free_buffer_head;

	/* 使用中のバッファのリスト */
	TAILQ_HEAD(used_buffer_head, buffer) used_buffer_head;

        /* bufferサイズ (4byteアラインされる) */
	size_t buffer_size;

	/* bufferを確保する際のまとまりの数 */
	int unit_count;

	/* 現在確保しているバッファの総数 */
	int current_buffers;

	pthread_mutex_t lock;
};

static int
allocate_buffer(
    buffer_manager_t *buffer_manager,
    alloc_ptr_t **alloc_ptr)
{
	alloc_ptr_t *new = NULL;
	buffer_t *tmp_buffer;
	char *tmp_ptr;
	int i;

	ASSERT(buffer_manager != NULL);
	if (alloc_ptr) {
		*alloc_ptr = NULL;
	}
	/* バッファをまとめて確保 */
	new = malloc(sizeof(alloc_ptr_t) +
	      ((sizeof(buffer_t) +
	        buffer_manager->buffer_size) *
	       buffer_manager->unit_count));
	if (new == NULL) {
		return 1;
	}
	/* alloc ptrをリストに追加 */
	new->padding = VERIFY_MAGIC;
	TAILQ_INSERT_HEAD(&buffer_manager->alloc_ptr_head, new, next);
	/* alloc ptr分のポインタを移動させて実際に使うまとめバッファ領域を差す */
	tmp_ptr = (char *)new + sizeof(alloc_ptr_t);
	/* まとめて確保したバッファをfree bufferに分割して登録する */
	for (i = 0; i < buffer_manager->unit_count; i++) {
		tmp_buffer = (buffer_t *)tmp_ptr;
		tmp_buffer->padding = VERIFY_MAGIC;
		TAILQ_INSERT_HEAD(&buffer_manager->free_buffer_head, tmp_buffer, next);
		/* 次のbufferのポインタへ移動 */
		tmp_ptr += buffer_manager->buffer_size + sizeof(buffer_t);
	}
	buffer_manager->current_buffers += buffer_manager->unit_count;
	if (alloc_ptr) {
		*alloc_ptr = new;
	}

	return 0;
}

int
buffer_manager_create(
    buffer_manager_t **buffer_manager,
    int glow,
    size_t buffer_size,
    int unit_count)
{
	alloc_ptr_t *new_alloc_ptr = NULL;
	buffer_manager_t *new = NULL;

	if (buffer_manager == NULL ||
	    (glow != BUFFER_MANAGER_GLOW_OFF &&
	     glow != BUFFER_MANAGER_GLOW_ON) ||
	    buffer_size == 0 ||
	    unit_count == 0) {
		errno = EINVAL;
		return 1;
	}
	*buffer_manager = NULL;
	/* 4byteにアラインする */
	buffer_size = (buffer_size - (buffer_size & 3)) + 4;
	/* buffer_manager領域の確保 */
	new = malloc(sizeof(buffer_manager_t));
	if (new == NULL) {
		goto fail;
	}
	memset(new, 0, sizeof(buffer_manager_t));
	/* allocate bufferに必要なものを先に初期化しておく */
	TAILQ_INIT(&new->alloc_ptr_head);
	TAILQ_INIT(&new->free_buffer_head);
	new->buffer_size = buffer_size;
	new->unit_count = unit_count;
	/* バッファの確保 */
	if (allocate_buffer(new, &new_alloc_ptr)) {
		goto fail;
	}
	/* その他初期化処理 */
	if (pthread_mutex_init(&new->lock, NULL)) {
		goto fail;

	}
	TAILQ_INIT(&new->used_buffer_head);
	new->glow = glow;
	*buffer_manager = new;

	return 0;

fail:
	free(new_alloc_ptr);
	free(new);

	return 1;
}

int
buffer_manager_destroy(
    buffer_manager_t *buffer_manager)
{
	alloc_ptr_t *alloc_ptr, *alloc_ptr_next;

	if (buffer_manager == NULL) {
		errno = EINVAL;
		return 1;
	}
	/*
         * 確保したメモリを開放
         * 中に何があったとかは興味ないのでざっくり消す
         */
	alloc_ptr = TAILQ_FIRST(&buffer_manager->alloc_ptr_head);
	while (alloc_ptr != NULL) {
		alloc_ptr_next = TAILQ_NEXT(alloc_ptr, next);
		TAILQ_REMOVE(&buffer_manager->alloc_ptr_head, alloc_ptr, next);
		ASSERT(alloc_ptr->padding == VERIFY_MAGIC);
		free(alloc_ptr);
		alloc_ptr = alloc_ptr_next;
	}
	pthread_mutex_destroy(&buffer_manager->lock);
	free(buffer_manager);

	return 0;
}

int
buffer_manager_get(
    buffer_manager_t *buffer_manager,
    void **data)
{
	int error = 0;
	buffer_t *free_buffer;

	if (buffer_manager == NULL ||
	    data == NULL) {
		errno = EINVAL;
		return 1;
	}
	*data = NULL;
	if (pthread_mutex_lock(&buffer_manager->lock)) {
		ABORT("failed in lock");
	}
	free_buffer = TAILQ_FIRST(&buffer_manager->free_buffer_head);
	if (free_buffer == NULL) {
		if (buffer_manager->glow == BUFFER_MANAGER_GLOW_ON) {
			/* 追加でバッファを確保 */
			if (allocate_buffer(buffer_manager, NULL)) {
				errno = ENOBUFS;
				error = 1;
				goto last;
			}
			free_buffer = TAILQ_FIRST(&buffer_manager->free_buffer_head);
			ASSERT(free_buffer != NULL);
		} else {
			errno = ENOBUFS;
			error = 1;
			goto last;
		}
	}
	/* 空きから使用領域に付け替える */
	TAILQ_REMOVE(&buffer_manager->free_buffer_head, free_buffer, next);
	TAILQ_INSERT_TAIL(&buffer_manager->used_buffer_head, free_buffer, next);
	/* 実際のデータポインタを返す */
	*data = (char *)free_buffer +  sizeof(buffer_t);
	/* 理屈上4バイトにアラインされていないといけない */
	ASSERT(((uint64_t)(*(char *)data) & 3) == 0);
last:
	if (pthread_mutex_unlock(&buffer_manager->lock)) {
		ABORT("failed in unlock");
	}
	
	return error;
}

int
buffer_manager_put(
    buffer_manager_t *buffer_manager,
    void *data)
{
	buffer_t *used_buffer;

	if (buffer_manager == NULL ||
	    data  == NULL) {
		errno = EINVAL;
		return 1;
	}
	/* bufferの構造体の先頭へポインタ移動 */
	used_buffer = (buffer_t *)((char *)data - sizeof(buffer_t));
	/* putするバッファが正しいものかpaddingのあたいから判定 */
	if (used_buffer->padding != VERIFY_MAGIC) {
		errno = EINVAL;
		return 1;
	}
	if (pthread_mutex_lock(&buffer_manager->lock)) {
		ABORT("failed in lock");
	}
	/* 使用から空き領域に付け替える */
	TAILQ_REMOVE(&buffer_manager->used_buffer_head, used_buffer, next);
	TAILQ_INSERT_TAIL(&buffer_manager->free_buffer_head, used_buffer, next);
	if (pthread_mutex_unlock(&buffer_manager->lock)) {
		ABORT("failed in unlock");
	}
	
	return 0;
}

int
buffer_manager_get_current_buffers(
    buffer_manager_t *buffer_manager,
    int *current_buffers)
{
	if (buffer_manager == NULL ||
	    current_buffers  == NULL) {
		errno = EINVAL;
		return 1;
	}
	if (pthread_mutex_lock(&buffer_manager->lock)) {
		ABORT("failed in lock");
	}
	*current_buffers = buffer_manager->current_buffers;
	if (pthread_mutex_unlock(&buffer_manager->lock)) {
		ABORT("failed in unlock");
	}
	
	return 0;
}
