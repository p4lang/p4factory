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

#include <stdlib.h>
#include <pthread.h>
#include <assert.h>

#include <p4utils/circular_buffer.h>
#include <p4utils/prio_scheduler.h>

/*
   All the dropping is handled by
   the underlying circular buffer
*/

/* Priority scheduler object */
struct prio_scheduler_s {
  int num_queues;              /* Number of FIFOs */
  circular_buffer_t **queues;  /* vector of FIFOs of elements */
  pthread_mutex_t lock;
};
 
prio_scheduler_t *prio_init(int size, int num_queues) {
  prio_scheduler_t *prio = malloc(sizeof(prio_scheduler_t));
  prio->num_queues = num_queues;

  prio->queues = calloc(prio->num_queues, sizeof(circular_buffer_t *));
  int i = 0;
  for (i = 0; i < prio->num_queues; i++) {
    prio->queues[i] = cb_init(size, CB_WRITE_DROP, CB_READ_RETURN);
  }

  pthread_mutex_init(&prio->lock, NULL);
  return prio;
}
 
void prio_destroy(prio_scheduler_t *prio) {
  pthread_mutex_destroy(&prio->lock);
  int i =0;
  for (i = 0; i < prio->num_queues; i++) {
    cb_destroy(prio->queues[i]);
  }
  free(prio->queues);
  free(prio);
}

/* Enque packet */
void prio_write(prio_scheduler_t *prio, void* elem, int queue_id) {
  pthread_mutex_lock(&prio->lock);
  assert(queue_id < prio->num_queues);
  cb_write(prio->queues[queue_id], elem);
  pthread_mutex_unlock(&prio->lock);
}
 
/* Deque packet, lower numeric number = higher priority */
void *prio_read(prio_scheduler_t *prio) {
  pthread_mutex_lock(&prio->lock);
  void* elem = NULL;
  int i=0;
  for (i=0; i < prio->num_queues; i++) {
    elem = cb_read(prio->queues[i]);
    if (elem != NULL) {
      break;
    }
  }
  pthread_mutex_unlock(&prio->lock);
  return elem;
}
