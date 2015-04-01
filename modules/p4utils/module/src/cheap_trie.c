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

#include "p4utils/cheap_trie.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

typedef struct node_s {
  struct node_s *branch[256];
  void *pref7[128];
  void *pref6[64];
  void *pref5[32];
  void *pref4[16];
  void *pref3[8];
  void *pref2[4];
  void *pref1[2];
  void *pref0[1];
  int branch_num;
  int pref_num;
  struct node_s *parent;
  int byte;
} node_t;

struct cheap_trie_s {
  node_t *root;
  int key_width_bytes;
};

static inline void allocate_node(node_t ** node) {
  *node = malloc(sizeof(node_t));
  memset(*node, 0, sizeof(node_t));
}

cheap_trie_t *cheap_trie_create(int key_width_bytes) {
  assert(key_width_bytes <= 64);
  cheap_trie_t *trie = malloc(sizeof(cheap_trie_t));
  trie->key_width_bytes = key_width_bytes;
  allocate_node(&trie->root);
  return trie;
}

static void destroy_node(node_t *node) {
  int i;
  for(i = 0; i < 256; i++) {
    if(node->branch[i]) {
      destroy_node(node->branch[i]);
    }
  }
  free(node);
}

void cheap_trie_destroy(cheap_trie_t *t) {
  destroy_node(t->root);
  free(t);
}

/* width is in bits */
void cheap_trie_insert(cheap_trie_t *trie,
		       uint8_t *prefix, int width,
		       void *data) {
  node_t *current_node = trie->root;
  uint8_t byte;
  while(width >= 8) {
    byte = *prefix;
    node_t *node = current_node->branch[byte];
    if(!node) {
      allocate_node(&node);
      node->byte = byte;
      node->parent = current_node;
      current_node->branch[byte] = node;
      current_node->branch_num++;
    }

    prefix++;
    width -= 8;
    current_node = node;
  }

  void **pref;
  switch(width) {
  case 0: 
    pref = &current_node->pref0[0];
    break;
  case 1:
    byte = (*prefix) >> 7;
    pref = &current_node->pref1[byte];
    break;
  case 2:
    byte = (*prefix) >> 6;
    pref = &current_node->pref2[byte];
    break;
  case 3:
    byte = (*prefix) >> 5;
    pref = &current_node->pref3[byte];
    break;
  case 4:
    byte = (*prefix) >> 4;
    pref = &current_node->pref4[byte];
    break;
  case 5:
    byte = (*prefix) >> 3;
    pref = &current_node->pref5[byte];
    break;
  case 6:
    byte = (*prefix) >> 2;
    pref = &current_node->pref6[byte];
    break;
  case 7:
    byte = (*prefix) >> 1;
    pref = &current_node->pref7[byte];
    break;
  }
  if(!(*pref)) current_node->pref_num++;
  *pref = data;
}

void *cheap_trie_get(cheap_trie_t *trie, uint8_t *key) {
  node_t *current_node = trie->root;
  uint8_t byte;
  int key_width = trie->key_width_bytes;
  void *data = NULL;

  while(key_width >= 0 && current_node) {
    byte = *key;

    if (current_node->pref7[byte >> 1])
      data = current_node->pref7[byte >> 1];
    else if (current_node->pref6[byte >> 2])
      data = current_node->pref6[byte >> 2];
    else if (current_node->pref5[byte >> 3])
      data = current_node->pref5[byte >> 3];
    else if (current_node->pref4[byte >> 4])
      data = current_node->pref4[byte >> 4];
    else if (current_node->pref3[byte >> 5])
      data = current_node->pref3[byte >> 5];
    else if (current_node->pref2[byte >> 6])
      data = current_node->pref2[byte >> 6];
    else if (current_node->pref1[byte >> 7])
      data = current_node->pref1[byte >> 7];
    else if (current_node->pref0[0])
      data = current_node->pref0[0];

    current_node = current_node->branch[byte];

    key++;
    key_width--;
  }

  return data;
}

void *cheap_trie_delete(cheap_trie_t *trie, uint8_t *prefix, int width) {
  node_t *current_node = trie->root;
  uint8_t byte;
  while(width >= 8) {
    byte = *prefix;
    node_t *node = current_node->branch[byte];

    if (!node) return NULL;

    prefix++;
    width -= 8;
    current_node = node;
  }

  void **pref;
  switch(width) {
  case 0: 
    pref = &current_node->pref0[0];
    break;
  case 1:
    byte = (*prefix) >> 7;
    pref = &current_node->pref1[byte];
    break;
  case 2:
    byte = (*prefix) >> 6;
    pref = &current_node->pref2[byte];
    break;
  case 3:
    byte = (*prefix) >> 5;
    pref = &current_node->pref3[byte];
    break;
  case 4:
    byte = (*prefix) >> 4;
    pref = &current_node->pref4[byte];
    break;
  case 5:
    byte = (*prefix) >> 3;
    pref = &current_node->pref5[byte];
    break;
  case 6:
    byte = (*prefix) >> 2;
    pref = &current_node->pref6[byte];
    break;
  case 7:
    byte = (*prefix) >> 1;
    pref = &current_node->pref7[byte];
    break;
  }
  if(!(*pref)) return NULL;
  void *data = *pref;

  *pref = NULL;
  current_node->pref_num--;
  while(current_node->pref_num == 0 && current_node->branch_num == 0) {
    node_t *tmp = current_node;
    current_node = current_node->parent;
    if(!current_node) break;
    current_node->branch[tmp->byte] = 0;
    free(tmp);
    current_node->branch_num--;
  }

  return data;
}

static void print_node(node_t *node, int width) {
  int i;
  printf("pref_num %d, branch_num %d\n", node->pref_num, node->branch_num);
  for (i = 0; i < 128; i++) {
    if(node->pref7[i])
      printf("%u / %d\n", i << 1, width + 1);
  }
  for (i = 0; i < 64; i++) {
    if(node->pref6[i])
      printf("%u / %d\n", i << 2, width + 2);
  }
  for (i = 0; i < 32; i++) {
    if(node->pref5[i])
      printf("%u / %d\n", i << 3, width + 3);
  }
  for (i = 0; i < 16; i++) {
    if(node->pref4[i])
      printf("%u / %d\n", i << 4, width + 4);
  }
  for (i = 0; i < 8; i++) {
    if(node->pref3[i])
      printf("%u / %d\n", i << 5, width + 5);
  }
  for (i = 0; i < 4; i++) {
    if(node->pref2[i])
      printf("%u / %d\n", i << 6, width + 6);
  }
  for (i = 0; i < 2; i++) {
    if(node->pref1[i])
      printf("%u / %d\n", i << 7, width + 7);
  }
  if(node->pref0[0])
    printf("/ %d\n", width);

  for (i = 0; i < 256; i++){
    if(node->branch[i]) {
      printf("-> %u\n", i);
      print_node(node->branch[i], width + 8);
    }
  }
}

void cheap_trie_print(cheap_trie_t *trie) {
  print_node(trie->root, 0);
}
