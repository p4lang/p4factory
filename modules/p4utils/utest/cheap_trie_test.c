#include <p4utils/cheap_trie.h>

#include <assert.h>
#include <ctype.h>
#include <stdio.h>

#define IPV4_BYTES 4

static void ipv4_str_to_bytes (char *str, uint8_t *bytes) {
  size_t index = 0;
  *(uint32_t *) bytes = 0;

  //  char *str2 = str; /* save the pointer */
  while (*str) {
    if (isdigit((unsigned char)*str)) {
      bytes[index] *= 10;
      bytes[index] += *str - '0';
    } else {
      index++;
    }
    str++;
  }
  /* printf("values in \"%s\": %d %d %d %d\n", str2, */
  /* 	 bytes[0], bytes[1], bytes[2], bytes[3]); */
  return;
}

int cheap_trie_main(int argc, char *argv[]) {
  cheap_trie_t *trie = cheap_trie_create(IPV4_BYTES);

  int dummy = 56;
  int *data;

  uint8_t ipv4[IPV4_BYTES];

  ipv4_str_to_bytes("192.168.0.0", ipv4);
  cheap_trie_insert(trie, ipv4, 16, &dummy);

  ipv4_str_to_bytes("192.168.0.1", ipv4);
  data = cheap_trie_get(trie, ipv4);
  assert(*data == dummy);

  cheap_trie_insert(trie, ipv4, 32, &dummy);

  data = cheap_trie_get(trie, ipv4);
  assert(*data == dummy);

  data = cheap_trie_get(trie, ipv4);
  assert(*data == dummy);

  ipv4_str_to_bytes("192.168.0.0", ipv4);
  data = cheap_trie_delete(trie, ipv4, 16);
  assert(data);

  data = cheap_trie_delete(trie, ipv4, 16);
  assert(!data);

  ipv4_str_to_bytes("192.168.0.1", ipv4);
  data = cheap_trie_get(trie, ipv4);
  assert(*data == dummy);

  int dummy1, dummy2;
  dummy1 = 16;
  dummy2 = 28;
  ipv4_str_to_bytes("91.189.0.0", ipv4);
  cheap_trie_insert(trie, ipv4, 16, &dummy1);
  ipv4_str_to_bytes("91.189.90.32", ipv4);
  cheap_trie_insert(trie, ipv4, 28, &dummy2);

  ipv4_str_to_bytes("91.189.90.41", ipv4);
  data = cheap_trie_get(trie, ipv4);
  assert(*data == dummy2);

  cheap_trie_destroy(trie);

  printf("All tests PASSED.\n");
  return 0;
}
