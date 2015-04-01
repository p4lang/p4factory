/*
Copyright 2013-present Barefoot Networks, Inc. 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <assert.h>
#include <sys/time.h>

#include <p4utils/circular_buffer.h>
 
/* Circular buffer object */
struct circular_buffer_s {
  int size;   /* maximum number of elements */
  int start;  /* index of oldest element */
  int count;
  void **elems;  /* vector of elements */
  cb_write_behavior_t write_behavior;
  cb_read_behavior_t read_behavior;
  pthread_mutex_t lock;
  pthread_cond_t cond_nonfull;
  pthread_cond_t cond_nonempty;
};
 
circular_buffer_t *cb_init(int size, cb_write_behavior_t wb, cb_read_behavior_t rb) {
  circular_buffer_t *cb = malloc(sizeof(circular_buffer_t));
  assert(size > 0);
  cb->size  = size; /* include empty elem */
  cb->start = 0;
  cb->count = 0;
  cb->elems = calloc(cb->size, sizeof(void *));
  cb->write_behavior = wb;
  cb->read_behavior  = rb;
  pthread_mutex_init(&cb->lock, NULL);
  pthread_cond_init(&cb->cond_nonfull, NULL);
  pthread_cond_init(&cb->cond_nonempty, NULL);
  return cb;
}
 
void cb_destroy(circular_buffer_t *cb) {
  pthread_cond_destroy(&cb->cond_nonfull);
  pthread_cond_destroy(&cb->cond_nonempty);
  pthread_mutex_destroy(&cb->lock);
  free(cb->elems);
  free(cb);
}

int cb_empty(circular_buffer_t* cb) {
  pthread_mutex_lock(&cb->lock);
  int ret = -1;
  if (cb->count == 0) {
    ret = 1;
  } else {
    ret = 0;
  }
  pthread_mutex_unlock(&cb->lock);
  return ret;
}

int cb_count(circular_buffer_t* cb) {
  pthread_mutex_lock(&cb->lock);
  //There is also the option of not acquiring lock for now - ideally we should
  int ret = cb->count;
  pthread_mutex_unlock(&cb->lock);
  return ret;
}

int cb_write(circular_buffer_t *cb, void* elem) {
  pthread_mutex_lock(&cb->lock);

  /* Overflow behaviors */
  if (cb->write_behavior == CB_WRITE_BLOCK) {
    while(cb->count == cb->size)
      pthread_cond_wait(&cb->cond_nonfull, &cb->lock);
  } else if (cb->write_behavior == CB_WRITE_DROP) {
    if (cb->count == cb->size) {
      pthread_mutex_unlock(&cb->lock);
      return 0;
    }
  }

  int end = (cb->start + cb->count) % cb->size;
  cb->elems[end] = elem;
  ++cb->count;
  if (cb->write_behavior == CB_WRITE_BLOCK) {
    pthread_cond_signal(&cb->cond_nonempty);
  }
  pthread_mutex_unlock(&cb->lock);
  return 1;
}
 
void *cb_read(circular_buffer_t *cb) {
  pthread_mutex_lock(&cb->lock);

  if (cb->read_behavior == CB_READ_BLOCK) {
    while(cb->count == 0)
      pthread_cond_wait(&cb->cond_nonempty, &cb->lock);
  } else if (cb->read_behavior == CB_READ_RETURN) {
    if (cb->count == 0) {
      pthread_mutex_unlock(&cb->lock);
      return NULL;
    }
  }

  void *elem = cb->elems[cb->start];
  cb->start = (cb->start + 1) % cb->size;
  --cb->count;
  if (cb->read_behavior == CB_READ_BLOCK) {
    pthread_cond_signal(&cb->cond_nonfull);
  }
  pthread_mutex_unlock(&cb->lock);
  return elem;
}

void *cb_read_with_wait(circular_buffer_t *cb, const struct timeval *timeout) {
  pthread_mutex_lock(&cb->lock);
  if(cb->count == 0) {
    if(0 == timeout) {
      pthread_cond_wait(&cb->cond_nonempty, &cb->lock);
    }
    else {
      struct timespec abs_timeout;
      struct timeval now, end_time;
      gettimeofday(&now,NULL);
      timeradd(&now, timeout, &end_time);
      abs_timeout.tv_sec = end_time.tv_sec;
      abs_timeout.tv_nsec = end_time.tv_usec * 1000UL;
      pthread_cond_timedwait(&cb->cond_nonempty, &cb->lock, &abs_timeout);
    }
  }

  void *elem = NULL;
  if(0 < cb->count) {
    elem = cb->elems[cb->start];
    cb->start = (cb->start + 1) % cb->size;
    --cb->count;
    pthread_cond_signal(&cb->cond_nonfull);
  }

  pthread_mutex_unlock(&cb->lock);
  return elem;
}

void cb_resize(circular_buffer_t *cb, const int new_size, cb_cleanup cb_cleanup_function) {
  pthread_mutex_lock(&cb->lock);
  assert(new_size > 0);

  /* Now shift the circular buffer using another buffer of new_size */
  void** new_buffer = calloc(new_size, sizeof(void *));
  assert(new_buffer != NULL);
  const int shift_num = (cb->count < new_size) ? cb->count : new_size;
  int i = 0;
  for (i = 0; i < shift_num; i++) {
    new_buffer[i] = cb->elems[(cb->start + i)%cb->size];
  }

  /* Clear out elements beyond cb->size */
  for (i = shift_num; i < cb->count; i++) {
    cb_cleanup_function(cb->elems[(cb->start + i)%cb->size]);
  }

  /* Reset state */
  cb->start = 0;
  cb->count = shift_num;
  cb->size  = new_size;

  /* free old pointer and reassign elems */
  free(cb->elems);
  cb->elems = new_buffer;

  pthread_mutex_unlock(&cb->lock);
}
