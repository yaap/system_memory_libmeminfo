/*
 * Copyright (C) 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MEM_EVENTS_BPF_TYES_H_
#define MEM_EVENTS_BPF_TYES_H_

#include <inttypes.h>

#define MEM_EVENT_OOM_KILL 0
#define MEM_EVENT_DIRECT_RECLAIM_BEGIN 1
#define MEM_EVENT_DIRECT_RECLAIM_END 2

// This always comes after the last valid event type
#define NR_MEM_EVENTS 3

struct mem_event_t {
    uint64_t pid;
    uint64_t type;
};

#endif /* MEM_EVENTS_BPF_TYES_H_ */
