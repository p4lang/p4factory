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

#include "p4utils/cheap_tcam.h"

#include "p4utils/lookup3.h"
#include "p4utils/tommyhashlin.h"
#include "p4utils/tommylist.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdint.h>

typedef struct tcam_hashmap_s {
  uint8_t *mask;
  tommy_hashlin hashmap;
  tommy_node node;
} tcam_hashmap_t;

struct cheap_tcam_s {
  int key_size;
  cheap_tcam_priority_fn get_priority;
  cheap_tcam_cmp_fn cmp;
  tommy_list hashmaps;
  uint8_t *masked_key;
};

cheap_tcam_t *cheap_tcam_create(int key_size,
				cheap_tcam_priority_fn get_priority,
				cheap_tcam_cmp_fn cmp) {
  cheap_tcam_t *tcam = malloc(sizeof(cheap_tcam_t));
  tcam->key_size = key_size;
  tcam->get_priority = get_priority;
  tcam->cmp = cmp;
  tcam->masked_key = malloc(key_size);
  tommy_list_init(&tcam->hashmaps);
  return tcam;
}

void cheap_tcam_destroy(cheap_tcam_t *tcam) {
  tommy_node* elem = tommy_list_head(&tcam->hashmaps);
  tommy_node* next;
  tcam_hashmap_t *tcam_hashmap;
  while(elem) {
    tcam_hashmap = (tcam_hashmap_t *) elem->data;
    tommy_hashlin_done(&tcam_hashmap->hashmap);
    free(tcam_hashmap->mask);
    next = elem->next;
    free(tcam_hashmap);
    elem = next;
  }
  
  free(tcam->masked_key);
  free(tcam);
}

void *cheap_tcam_search(cheap_tcam_t *tcam,
			uint8_t *key) {
  tommy_list *hashmaps = &tcam->hashmaps;
  tcam_hashmap_t *tcam_hashmap;
  int max_priority = -1;
  int priority;
  void *entry;
  void *result = NULL;
  uint32_t hash;

  uint8_t *masked_key = tcam->masked_key;

  tommy_node* elem = tommy_list_head(hashmaps);
  while(elem) {
    tcam_hashmap = (tcam_hashmap_t *) elem->data;
    int i;
    for (i = 0; i < tcam->key_size; i++) {
      masked_key[i] = key[i] & tcam_hashmap->mask[i];
    }
    hash = hashlittle(masked_key, tcam->key_size, 0);
    /* TODO !!!: only returns the first one, what about priority !? */
    entry = tommy_hashlin_search(&tcam_hashmap->hashmap,
				 tcam->cmp,
				 masked_key, hash);
    if(entry) {
      priority = tcam->get_priority(entry);
      if(priority > max_priority){
    	max_priority = priority;
    	result = entry;
      }
    }

    elem = elem->next;
  }

  return result;
}

void cheap_tcam_insert(cheap_tcam_t *tcam,
		       uint8_t *mask,
		       uint8_t *key,
		       cheap_tcam_node *node,
		       void *data) {
  tommy_list *hashmaps = &tcam->hashmaps;
  tcam_hashmap_t *tcam_hashmap;
  uint32_t hash = hashlittle(key, tcam->key_size, 0);
  tommy_node* elem = tommy_list_head(hashmaps);
  
  while(elem) {
    tcam_hashmap = (tcam_hashmap_t *) elem->data;
    if(!memcmp(mask, tcam_hashmap->mask, tcam->key_size)) {
      tommy_hashlin_insert(&tcam_hashmap->hashmap, node, data, hash);
      return;
    }
    elem = elem->next;
  }

  tcam_hashmap = malloc(sizeof(tcam_hashmap_t));
  tommy_hashlin_init(&tcam_hashmap->hashmap);
  tcam_hashmap->mask = malloc(tcam->key_size);
  memcpy(tcam_hashmap->mask, mask, tcam->key_size);
  tommy_list_insert_head(hashmaps, &tcam_hashmap->node, tcam_hashmap);
  tommy_hashlin_insert(&tcam_hashmap->hashmap, node, data, hash);
}

void cheap_tcam_delete(cheap_tcam_t *tcam,
		       uint8_t *mask,
		       uint8_t *key,
		       cheap_tcam_node *node) {
  tommy_list *hashmaps = &tcam->hashmaps;
  tcam_hashmap_t *tcam_hashmap;
  tommy_node* elem = tommy_list_head(hashmaps);

  while(elem) {
    tcam_hashmap = (tcam_hashmap_t *) elem->data;
    if(!memcmp(mask, tcam_hashmap->mask, tcam->key_size)) {
      tommy_hashlin_remove_existing(&tcam_hashmap->hashmap, node);
      return;
    }
    elem = elem->next;
  }
}
