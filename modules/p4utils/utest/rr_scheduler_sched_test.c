#include <stdio.h>
#include <assert.h>

#include <p4utils/rr_scheduler.h>

#define SIZE 20
#define NUM_ELEMS 20

int rr_scheduler_sched(int argc, char *argv[]) {
  rr_scheduler_t *rr = rr_init(SIZE, 4);

  /* Test 1: Write 20 elements in and read them out */
  const int elems[20]  = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
  const int result[20] = {1, 6, 11, 16, 2, 7, 12, 17, 3, 8, 13, 18, 4, 9, 14, 19, 5, 10, 15, 20};
  const int result2[5] = {1, 2, 3, 4, 5};
  const int result3[6] = {1, 6, 2, 3, 4, 5};

  /* Write data in */
  int i = 0;
  for (i = 0; i < NUM_ELEMS; i++) {
    rr_write(rr, (void *) &elems[i], i / (20 / 4.0) );
  }

  /* Read it out */
  for (i = 0; i < NUM_ELEMS; i++) {
    void *elem = rr_read(rr);
    assert(*(int *) elem == result[i]);
  }

  /* Test 2: Test work conserving behavior */
  for (i = 0; i < 5; i++) {
    rr_write(rr, (void *) &elems[i], i / (20 / 4.0) );
  }

  for (i = 0; i < 5; i++) {
    void *elem = rr_read(rr);
    assert(*(int *) elem == result2[i]);
  }

  /* Test 3: Test work conserving behavior */
  for (i = 0; i < 6; i++) {
    rr_write(rr, (void *) &elems[i], i / (20 / 4.0) );
  }

  for (i = 0; i < 6; i++) {
    void *elem = rr_read(rr);
    assert(*(int *) elem == result3[i]);
  }


  /* Test 4: Reads should all return null here */
  for (i = 0; i < 10; i++) {
    assert(rr_read(rr) == NULL);
  }
 

  rr_destroy(rr);
  printf("Test passed\n");

  return 0;
}
