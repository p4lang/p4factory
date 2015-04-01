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
* p4_mempool.c
*   Memory pool implementation using TLSF (two level segregate fit)
*/

#include "p4utils/p4_mempool.h"


inline size_t p4_mempool_init(size_t size, p4_mempool_handle_t pool_handle)
{
    return init_memory_pool(size, (void *)pool_handle);
}

inline void p4_mempool_destroy(p4_mempool_handle_t pool_handle)
{
    destroy_memory_pool((void *) pool_handle);
}

inline size_t p4_mempool_add(p4_mempool_handle_t pool_handle, size_t size, p4_mempool_handle_t h2)
{
    return add_new_area((void *)pool_handle, size, (void *)h2);
}

inline size_t p4_mempool_get_used(p4_mempool_handle_t pool_handle)
{
    return get_used_size((void *)pool_handle);
}

inline size_t p4_mempool_get_max(p4_mempool_handle_t pool_handle)
{
    return get_max_size((void *)pool_handle);
}

inline void *p4_mempool_alloc(size_t size, p4_mempool_handle_t pool_handle)
{
    return malloc_ex(size, (void *)pool_handle);
}

inline void p4_mempool_free(void *ptr, p4_mempool_handle_t pool_handle)
{
    free_ex(ptr, (void *)pool_handle);
}

inline void *p4_mempool_realloc(void *ptr, size_t new_size, p4_mempool_handle_t pool_handle)
{
    return realloc_ex(ptr, new_size, (void *)pool_handle);
}

inline void *p4_mempool_calloc(size_t n_elem, size_t elem_size, p4_mempool_handle_t pool_handle)
{
    return calloc_ex(n_elem, elem_size, (void *)pool_handle);
}


