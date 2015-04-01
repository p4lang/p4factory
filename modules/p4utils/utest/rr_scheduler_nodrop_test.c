#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <p4utils/rr_scheduler.h>

#define SIZE 1024
#define NUM_ELEMS 1024

int *elems;

void *rr_no_drop_read_data(void *arg) {
  int i;
  rr_scheduler_t *rr = (rr_scheduler_t *) arg;
  
  for (i = 0; i < NUM_ELEMS; i++) {
    void *elem = rr_read(rr);
    assert(*(int *) elem == elems[i]);
  }

  return NULL;
}

int rr_scheduler_no_drop(int argc, char *argv[]) {
  pthread_t thread;
  elems = calloc(NUM_ELEMS, sizeof(int));
  int i;
  for (i = 0; i < NUM_ELEMS; i++)
    elems[i] = rand();

  rr_scheduler_t *rr = rr_init(SIZE, 1);

  for (i = 0; i < NUM_ELEMS; i++) {
    rr_write(rr, (void *) &elems[i], 0);
  }

  pthread_create(&thread, NULL, rr_no_drop_read_data, (void *) rr);

  pthread_join(thread, NULL);
  
  rr_destroy(rr);
  free(elems);
  printf("Test passed\n");

  return 0;
}
