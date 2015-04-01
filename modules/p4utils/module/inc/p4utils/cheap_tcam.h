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

#ifndef _CHEAP_TCAM_H
#define _CHEAP_TCAM_H

#include <stdint.h>

#include <p4utils/tommyhashlin.h>

typedef struct cheap_tcam_s cheap_tcam_t;

typedef int (*cheap_tcam_priority_fn)(const void *entry);
typedef int (*cheap_tcam_cmp_fn)(const void *key, const void *entry);

typedef tommy_hashlin_node cheap_tcam_node;

cheap_tcam_t *cheap_tcam_create(int key_size,
				cheap_tcam_priority_fn get_priority,
				cheap_tcam_cmp_fn cmp);

void cheap_tcam_destroy(cheap_tcam_t *tcam);

void cheap_tcam_insert(cheap_tcam_t *tcam,
		       uint8_t *mask,
		       uint8_t *key,
		       cheap_tcam_node *node,
		       void *data);

void *cheap_tcam_search(cheap_tcam_t *tcam, uint8_t *key);

void cheap_tcam_delete(cheap_tcam_t *tcam,
		       uint8_t *mask,
		       uint8_t *key,
		       cheap_tcam_node *node);
#endif
