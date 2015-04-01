#include <stdio.h>
#include <assert.h>

#include <p4utils/prio_scheduler.h>

#define SIZE 20
#define NUM_ELEMS 20

int prio_scheduler_sched(int argc, char *argv[]) {
  prio_scheduler_t *prio = prio_init(SIZE, 4);

  /* Test 1: Write 20 elements in and read them out */
  const int elems[20]  = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
  const int result[20] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
  const int result2[20]= {16, 17, 18, 19, 20, 11, 12, 13, 14, 15, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5};
  const int result3[6]= {6, 1, 2, 3, 4, 5};

  /* Write data in */
  int i = 0;
  for (i = 0; i < NUM_ELEMS; i++) {
    prio_write(prio, (void *) &elems[i], i / (20 / 4.0) );
  }

  /* Read it out */
  for (i = 0; i < NUM_ELEMS; i++) {
    void *elem = prio_read(prio);
    assert(*(int *) elem == result[i]);
  }

  /* Test 2: Write in 20 elements but with inverted priorties, so that they come out in reverse */
  /* Write data in */
  for (i = 0; i < NUM_ELEMS; i++) {
    prio_write(prio, (void *) &elems[i], (19 - i) / (20 / 4.0) );
  }

  /* Read it out */
  for (i = 0; i < NUM_ELEMS; i++) {
    void *elem = prio_read(prio);
    assert(*(int *) elem == result2[i]);
  }

  /* Test 3: Test work conserving behavior */
  /* Write data in */
  for (i = 0; i < 6; i++) {
    prio_write(prio, (void *) &elems[i], (19 - i) / (20 / 4.0) );
  }

  /* Read it out */
  for (i = 0; i < 6; i++) {
    void *elem = prio_read(prio);
    assert(*(int *) elem == result3[i]);
  }

  /* Test 4: Reads should all return null here */
  for (i = 0; i < 10; i++) {
    assert(prio_read(prio) == NULL);
  }
 

  prio_destroy(prio);
  printf("Test passed\n");

  return 0;
}
