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

#include <elfutils/elf-file.h>

#include <elf.h>

#include <memory>
#include <vector>

namespace android {
namespace elfutils {

// Class to compare ELF binaries (shared libraries, executables).
//
// This class provides methods to compare:
//
// - Executable header (Elf_Ehdr)
// - Program headers (Elf_Phdr)
// - Section contents
// - Section headers (Elf_Shdr)
class ElfComparator {
  public:
    virtual ~ElfComparator() = default;
    static std::unique_ptr<ElfComparator> create(ElfFile& file1, ElfFile& file2);

    virtual bool compareHeaders() = 0;
    virtual bool compareProgramHeaders() = 0;
    virtual bool compareSectionHeaders() = 0;
    virtual bool compareSections() = 0;
};

}  // namespace elfutils
}  // namespace android
