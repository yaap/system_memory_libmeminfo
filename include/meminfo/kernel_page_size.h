/*
 * Copyright (C) 2024 The Android Open Source Project
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

#pragma once

#include <unistd.h>

namespace android {
namespace meminfo {

/*
 * Android emulates the userspace page size on some x86_64 emulators.
 * The kernel page size still remains 4KiB (0x1000).
 *
 */
#if defined(__x86_64__)
static inline size_t kernel_page_size(void) {
    return 0x1000;
}
#else
static inline size_t kernel_page_size(void) {
    return getpagesize();
}
#endif

/* The number of kernel pages covered by size */
static inline size_t nr_kernel_pages(size_t size) {
    return size / kernel_page_size();
}

/*
 * NOTE: For all cases except Android x86_64 page size emulators,
 * kernel_page_size == page_size, and the below conversions are
 * effectively no-ops.
 */

/* The number of kernel pages in a @nr_pages userspace pages */
static inline size_t nr_pgs_to_nr_kernel_pgs(size_t nr_pages) {
    return nr_pages * nr_kernel_pages(getpagesize());
}

/* The number of userspace pages in a @nr_pages kernel pages */
static inline size_t nr_kernel_pgs_to_nr_pgs(size_t nr_pages) {
    return nr_pages / nr_kernel_pages(getpagesize());
}

}  // namespace meminfo
}  // namespace android
