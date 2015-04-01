#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <p4utils/rr_scheduler.h>

#define SIZE 32
#define NUM_ELEMS 36

int *elems;

void *rr_drop_read_data(void *arg) {
  int i;
  rr_scheduler_t *rr = (rr_scheduler_t *) arg;

  for (i = 0; i < NUM_ELEMS; i++) {
    void *elem = rr_read(rr);
    if (i < SIZE) {
      assert(*(int *) elem == elems[i]);
    } else {
      assert(elem == NULL);
    }
  }

  return NULL;
}

int rr_scheduler_drop(int argc, char *argv[]) {
  pthread_t thread;
  elems = calloc(NUM_ELEMS, sizeof(int));
  int i;
  for (i = 0; i < NUM_ELEMS; i++)
    elems[i] = rand();

  rr_scheduler_t *rr = rr_init(SIZE, 1);

  for (i = 0; i < NUM_ELEMS; i++) {
    rr_write(rr, (void *) &elems[i], 0);
  }

  pthread_create(&thread, NULL, rr_drop_read_data, (void *) rr);
  pthread_join(thread, NULL);
  
  rr_destroy(rr);
  free(elems);
  printf("Test passed\n");

  return 0;
}
