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

#ifndef _CHEAP_TRIE_H
#define _CHEAP_TRIE_H

#include <stdint.h>

typedef struct cheap_trie_s cheap_trie_t;

cheap_trie_t *cheap_trie_create(int key_width_bytes);

void cheap_trie_destroy(cheap_trie_t *t);

void cheap_trie_insert(cheap_trie_t *trie,
		       uint8_t *prefix, int width,
		       void *data);

void *cheap_trie_get(cheap_trie_t *trie, uint8_t *key);

void *cheap_trie_delete(cheap_trie_t *trie, uint8_t *prefix, int width);

void cheap_trie_print(cheap_trie_t *trie);

#endif
