/*
 * Copyright (C) 2025 The Android Open Source Project
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

#include <elfutils/elf-file.h>
#include <string>

namespace android {
namespace elfpolicy {

constexpr size_t kMaxSupportedPageSize = 0x4000;

// Checks if a 64-bit ELF file has its loadable segments aligned to at least
// the specified page size.
//
// Returns true if the file is compatible, false otherwise.
// On failure, error_msg will be populated with a descriptive error.
// 32-bit ELF files are considered compatible by this check.
bool VerifyLoadSegmentsAlignment(const elfutils::ElfFile& elfFile, uint64_t pageSize,
                                 std::string& errorMsg);

// Validates that the PT_GNU_RELRO segment(s) in a 64-bit ELF file is valid and
// correctly aligned for the specified page size.
//
// Returns true if the segment is valid or absent, false otherwise.
// On failure, error_msg will be populated with a descriptive error.

bool VerifyRelroSegments(const elfutils::ElfFile& elfFile, uint64_t pageSize,
                         std::string& errorMsg);

}  // namespace elfpolicy
}  // namespace android
