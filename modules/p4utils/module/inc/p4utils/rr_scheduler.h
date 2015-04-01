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

#ifndef _RR_SCHEDULER_H
#define _RR_SCHEDULER_H

typedef struct rr_scheduler_s rr_scheduler_t;

rr_scheduler_t *rr_init(int size, int num_queues);

void rr_destroy(rr_scheduler_t *rr);

void rr_write(rr_scheduler_t *rr, void* elem, int queue_id);

void *rr_read(rr_scheduler_t *rr);

#endif
