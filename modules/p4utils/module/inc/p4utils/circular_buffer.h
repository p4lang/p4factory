#ifndef _CIRCULAR_BUFFER_H
#define _CIRCULAR_BUFFER_H

struct timeval;

typedef struct circular_buffer_s circular_buffer_t;

/* Different kinds of circular buffer behaviour */
typedef enum {CB_WRITE_BLOCK, CB_WRITE_DROP} cb_write_behavior_t;
typedef enum {CB_READ_BLOCK, CB_READ_RETURN} cb_read_behavior_t;
typedef void (*cb_cleanup)(void *);

circular_buffer_t *cb_init(int size, cb_write_behavior_t wb, cb_read_behavior_t rb);

void cb_destroy(circular_buffer_t *cb);

int cb_empty(circular_buffer_t* cb);

int cb_count(circular_buffer_t* cb);

int cb_write(circular_buffer_t *cb, void* elem);

void *cb_read(circular_buffer_t *cb);

void *cb_read_with_wait(circular_buffer_t *cb, const struct timeval *timeout);

void cb_resize(circular_buffer_t *cb, const int new_size, cb_cleanup cb_cleanup_function);

#endif
