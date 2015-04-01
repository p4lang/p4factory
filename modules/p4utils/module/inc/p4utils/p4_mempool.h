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

/*
*   p4_mempool.h
*/

#ifndef _P4_MEMPOOL_H
#define  _P4_MEMPOOL_H
#include "p4utils/tlsf.h"


typedef void *p4_mempool_handle_t;

size_t p4_mempool_init(size_t size, p4_mempool_handle_t pool_handle);
void p4_mempool_destroy(p4_mempool_handle_t pool_handle);
size_t p4_mempool_add(p4_mempool_handle_t pool_handle, size_t size, p4_mempool_handle_t h2);
size_t p4_mempool_get_used(p4_mempool_handle_t pool_handle);
size_t p4_mempool_get_max(p4_mempool_handle_t pool_handle);

void *p4_mempool_alloc(size_t size, p4_mempool_handle_t pool_handle);
void p4_mempool_free(void *ptr, p4_mempool_handle_t pool_handle);
void *p4_mempool_realloc(void *ptr, size_t new_size, p4_mempool_handle_t pool_handle);
void *p4_mempool_calloc(size_t n_elem, size_t elem_size, p4_mempool_handle_t pool_handle);


#endif

