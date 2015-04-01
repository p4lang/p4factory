#include <p4utils/cheap_tcam.h>

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdint.h>

typedef struct entry_s {
  uint32_t key;
  uint32_t mask;
  int priority;
  int data;
  cheap_tcam_node node;
} entry_t;

int get_priority(const void *entry) {
  return ((entry_t *) entry)->priority;
}

int cmp(const void *key, const void *entry) {
  return memcmp(key, &((entry_t *) entry)->key, 4);
}

int cheap_tcam_main(int argc, char *argv[]) {
  cheap_tcam_t *tcam = cheap_tcam_create(4, get_priority, cmp);

  entry_t entry1;
  entry1.key = 1;
  entry1.mask = 1;
  entry1.priority = 1;
  entry1.data = 99;

  cheap_tcam_insert(tcam, (uint8_t *) &entry1.mask, (uint8_t *) &entry1.key,
  		    &entry1.node, &entry1);
  
  uint32_t key = 3;
  entry_t *res = cheap_tcam_search(tcam, (uint8_t *) &key);
  assert(res->data == 99);

  key = 1;
  res = cheap_tcam_search(tcam, (uint8_t *) &key);
  assert(res->data == 99);

  key = 2;
  res = cheap_tcam_search(tcam, (uint8_t *) &key);
  assert(!res);

  cheap_tcam_delete(tcam, (uint8_t *) &entry1.mask, (uint8_t *) &entry1.key,
  		    &entry1.node);

  key = 3;
  res = cheap_tcam_search(tcam, (uint8_t *) &key);
  assert(!res);

  return 0;
}
