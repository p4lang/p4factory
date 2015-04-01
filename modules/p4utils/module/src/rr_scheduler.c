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
#include <stdio.h>
#include <pthread.h>
#include <assert.h>

#include <p4utils/tommylist.h>
#include <p4utils/circular_buffer.h>
#include <p4utils/rr_scheduler.h>

/*
   All the dropping is handled by
   the underlying circular buffer
*/

/* Linked list for DRR queues and helper functions */
struct rr_ll_node {
  tommy_node node;
  int queue_id;
};

int exists_in_ll(tommy_list* ll, int queue_id) {
 tommy_node* i = tommy_list_head(ll);
 while (i) {
     struct rr_ll_node* rr_node = i->data;
     if (rr_node->queue_id == queue_id) {
       return 1;
     }
     i = i->next; // go to the next element
 }
 return 0;
}

int remove_head(tommy_list* ll) {
  tommy_node* head = tommy_list_head(ll);
  struct rr_ll_node* obj = tommy_list_remove_existing(ll, head);
  return obj->queue_id;
}

void insert_tail(tommy_list* ll, int queue_id) {
  struct rr_ll_node* obj = malloc(sizeof(struct rr_ll_node));
  obj->queue_id = queue_id;
  tommy_list_insert_tail(ll, &(obj->node), obj);
}

/* DRR scheduler object */
struct rr_scheduler_s {
  int num_queues; /* Number of FIFOs */
  tommy_list* active_list;     /* Currently active queues */
  circular_buffer_t **queues;  /* vector of FIFOs of elements */
  pthread_mutex_t lock;
};
 
rr_scheduler_t *rr_init(int size, int num_queues) {
  rr_scheduler_t *rr = malloc(sizeof(rr_scheduler_t));
  rr->num_queues = num_queues;
  rr->active_list = malloc(sizeof(tommy_list));
  tommy_list_init(rr->active_list);

  rr->queues = calloc(rr->num_queues, sizeof(circular_buffer_t *));
  int i = 0;
  for (i = 0; i < rr->num_queues; i++) {
    rr->queues[i] = cb_init(size, CB_WRITE_DROP, CB_READ_RETURN);
  }

  pthread_mutex_init(&rr->lock, NULL);
  return rr;
}
 
void rr_destroy(rr_scheduler_t *rr) {
  pthread_mutex_destroy(&rr->lock);

  /* Clean up active list */
  tommy_node* cur_node = tommy_list_head(rr->active_list);
  while (cur_node) {
     tommy_node* cur_node_next = cur_node->next; // saves the next element before freeing
     free(cur_node->data); // frees the object allocated memory
     cur_node = cur_node_next; // goes to the next element
  }
  free(rr->active_list);

  int i =0;
  for (i = 0; i < rr->num_queues; i++) {
    cb_destroy(rr->queues[i]);
  }
  free(rr->queues);
  free(rr);
}

/* Enque packet */
void rr_write(rr_scheduler_t *rr, void* elem, int queue_id) {
  pthread_mutex_lock(&rr->lock);

  assert(queue_id < rr->num_queues);
  if (! exists_in_ll(rr->active_list, queue_id)) {
   insert_tail(rr->active_list, queue_id);
  }
  cb_write(rr->queues[queue_id], elem);
  pthread_mutex_unlock(&rr->lock);
}
 
/* Deque packet */
void *rr_read(rr_scheduler_t *rr) {
  pthread_mutex_lock(&rr->lock);
  void* elem = NULL;
  int queue_id = 0;
  while (! tommy_list_empty(rr->active_list)) {
    queue_id = remove_head(rr->active_list);
    elem = cb_read(rr->queues[queue_id]);
    if (elem != NULL) {
      if (! cb_empty(rr->queues[queue_id])) insert_tail(rr->active_list, queue_id);
      break;
    }
  }
  pthread_mutex_unlock(&rr->lock);
  return elem;
}
