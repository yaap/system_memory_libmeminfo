/*
 * Copyright (C) 2022 The Android Open Source Project
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

namespace android {
namespace smapinfo {

// Populates the input set with all pids present in the /proc directory. Only
// returns false if /proc could not be opened, returns true otherwise.
bool get_all_pids(std::set<pid_t>* pids);

// Sorts processes provided in 'pids' by memory usage (or oomadj score) and
// prints them. Returns false in the following failure cases:
// a) system memory information could not be read,
// b) swap offsets could not be counted for some process,
// c) reset_wss is true but the working set for some process could not be reset.
bool procrank(uint64_t pgflags, uint64_t pgflags_mask, const std::set<pid_t>& pids, bool get_oomadj,
              bool get_wss, int sort_order, bool reverse_sort, std::stringstream& out,
              std::stringstream& err);

}  // namespace smapinfo
}  // namespace android
