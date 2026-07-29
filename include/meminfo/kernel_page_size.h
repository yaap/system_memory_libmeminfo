/*
 * Copyright (C) 2026 The Android Open Source Project
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

#include <limits.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

namespace android {
namespace meminfo {

/*
 * Returns kernel page size from /proc/self/smaps.
 * This is required for x86_64 guests that emulate a 16KB page size
 * to userspace, but the underlying kernel still operates on 4KB pages.
 *
 * Returns -1 on failure.
 */
static inline int kernel_page_size() {
    static const int kpage_size = [] {
        std::ifstream smaps("/proc/self/smaps");
        std::string line;
        if (!smaps) {
            return -1;
        }

        while (std::getline(smaps, line)) {
            if (!line.starts_with("KernelPageSize:")) continue;

            std::stringstream ss(line);
            std::istream_iterator<std::string> begin(ss);
            std::istream_iterator<std::string> end;
            std::vector<std::string> fields(begin, end);

            // The expected format is:
            //     "KernelPageSize:        <size> kB"
            if (fields.size() < 3 || fields[2] != "kB") {
                return -1;
            }

            const char* start = fields[1].c_str();
            char* endptr;
            unsigned long page_size_kb = strtoul(start, &endptr, 10);
            if (page_size_kb == 0 || page_size_kb == ULONG_MAX || (page_size_kb % 4 != 0) ||
                start == endptr || *endptr != '\0') {
                return -1;
            }

            return static_cast<int>(page_size_kb * 1024);
        }

        return -1;
    }();

    return kpage_size;
}

}  // namespace meminfo
}  // namespace android
