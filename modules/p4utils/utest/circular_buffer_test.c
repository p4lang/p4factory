#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <p4utils/circular_buffer.h>

#define SIZE 32
#define NUM_ELEMS 1024

int *elems;

void free_elems(void* elem) {
  free(elem);
}

void *read_data(void *arg) {
  int i;
  circular_buffer_t *cb = (circular_buffer_t *) arg;
  
  for (i = 0; i < NUM_ELEMS; i++) {
    /* printf("reading %d\n", i); */
    void *elem = cb_read(cb);
    assert(*(int *) elem == elems[i]);
  }

  return NULL;
}

int circular_buffer_main(int argc, char *argv[]) {
  pthread_t thread;
  elems = calloc(NUM_ELEMS, sizeof(int));
  int i;
  for (i = 0; i < NUM_ELEMS; i++)
    elems[i] = rand();

  circular_buffer_t *cb = cb_init(SIZE, CB_WRITE_BLOCK, CB_READ_BLOCK);

  pthread_create(&thread, NULL, read_data, (void *) cb);

  for (i = 0; i < NUM_ELEMS; i++) {
    /* printf("writing %d\n", i); */
    cb_write(cb, (void *) &elems[i]);
  }

  pthread_join(thread, NULL);

  // resized queue
  pthread_t resized_thread;

  cb_resize(cb, SIZE / 2, free_elems);

  pthread_create(&resized_thread, NULL, read_data, (void *) cb);

  for (i = 0; i < NUM_ELEMS; i++) {
    /* printf("writing %d\n", i); */
    cb_write(cb, (void *) &elems[i]);
  }

  pthread_join(resized_thread, NULL);
  // end of resized queue

  cb_destroy(cb);
  free(elems);
  printf("Test passed\n");

  return 0;
}
