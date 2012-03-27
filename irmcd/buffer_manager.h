#ifndef BUFFER_MANAGER_H
#define BUFFER_MANAGER_H

#define BUFFER_MANAGER_GLOW_OFF 1
#define BUFFER_MANAGER_GLOW_ON  2

typedef struct buffer_manager buffer_manager_t;

int buffer_manager_create(
    buffer_manager_t **buffer_manager,
    int glow,
    size_t buffer_size,
    int unit_count);

int buffer_manager_destroy(
    buffer_manager_t *buffer_manager);

int buffer_manager_get(
    buffer_manager_t *buffer_manager,
    void **data);

int buffer_manager_put(
    buffer_manager_t *buffer_manager,
    void *data);

int buffer_manager_get_current_buffers(
    buffer_manager_t *buffer_manager,
    int *current_buffers);

#endif

