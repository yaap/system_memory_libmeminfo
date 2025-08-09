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

#pragma once

#include <sys/types.h>
#include <optional>
#include <string>
#include <vector>

#include <assert.h>

#include <elf.h>

namespace android {
namespace elfutils {

// Section content representation
typedef struct {
    std::vector<char> data;  // Raw content of the data section.
    uint64_t size;           // Size of the data section.
    std::string name;        // The name of the section.
    uint16_t index;          // Index of the section.
} Elf_Sc;

// Class to represent an ELF file.
//
// An ELF file is formed by 4 parts:
//
// - Executable header.
// - Program headers (present in executables or shared libraries).
// - Sections (.interp, .init, .plt, .text, .rodata, .data, .bss, .shstrtab, etc).
// - Section headers.
//
//                ______________________
//                |                    |
//                | Executable header  |
//                |____________________|
//                |                    |
//                |                    |
//                |  Program headers   |
//                |                    |
//                |____________________|
//                |                    |
//                |                    |
//                |      Sections      |
//                |                    |
//                |____________________|
//                |                    |
//                |                    |
//                |  Section headers   |
//                |                    |
//                |____________________|
//
//
// The structs defined in linux for ELF parts can be found in:
//
// https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/elf.h
// https://cs.android.com/android/platform/superproject/main/+/main:bionic/libc/kernel/uapi/linux/elf.h
class ElfFile {
  public:
    static std::unique_ptr<ElfFile> create(const std::string& path);
    virtual ~ElfFile() = default;
    virtual bool is32Bit() const = 0;
    virtual bool is64Bit() const = 0;
    virtual const std::string& getPath() const = 0;
    virtual const std::vector<Elf_Sc>& getSections() const = 0;
    virtual std::optional<int64_t> getMinLoadSegmentAlignment() = 0;
};

// Forward declare ElfParser so that we can friend it
template <typename>
class ElfParser;

// Expose the concrete implementation for use by classes that operate on ELF files
// e.g. ElfParser, ElfWriter, ElfComparator, ...
template <typename Ehdr_t, typename Phdr_t, typename Shdr_t, typename Dyn_t>
class ElfFileImpl : public ElfFile {
  public:
    using ElfFile_t = ElfFileImpl<Ehdr_t, Phdr_t, Shdr_t, Dyn_t>;
    using Elf_Ehdr = Ehdr_t;
    using Elf_Phdr = Phdr_t;
    using Elf_Shdr = Shdr_t;
    using Elf_Dyn = Dyn_t;

    ElfFileImpl(const std::string& path) : mPath(path) {}
    virtual ~ElfFileImpl() = default;

    bool is32Bit() const override { return std::is_same<Ehdr_t, Elf32_Ehdr>::value; }
    bool is64Bit() const override { return std::is_same<Ehdr_t, Elf64_Ehdr>::value; }
    const std::string& getPath() const override { return mPath; }
    const std::vector<Elf_Sc>& getSections() const override { return mSections; }
    std::optional<int64_t> getMinLoadSegmentAlignment() override;

    // Const accessors for serialization and inspection
    const Ehdr_t& getEhdr() const { return mEhdr; }
    const std::vector<Phdr_t>& getPhdrs() const { return mPhdrs; }
    const std::vector<Shdr_t>& getShdrs() const { return mShdrs; }

    // Methods for manipulating the dynamic section
    bool getDynamicEntries(std::vector<Elf_Dyn>& entries) const;
    bool setDynamicEntries(const std::vector<Elf_Dyn>& entries);

  protected:
    Elf_Ehdr mEhdr;
    std::vector<Elf_Phdr> mPhdrs;
    std::vector<Elf_Shdr> mShdrs;
    std::vector<Elf_Sc> mSections;
    const std::string mPath;

    // Grant friendship to ElfParserImpl as it needs to populate the ElfFileImpl fields.
    template <typename>
    friend class ElfParser;
};

using Elf32_File = ElfFileImpl<Elf32_Ehdr, Elf32_Phdr, Elf32_Shdr, Elf32_Dyn>;
using Elf64_File = ElfFileImpl<Elf64_Ehdr, Elf64_Phdr, Elf64_Shdr, Elf64_Dyn>;

}  // namespace elfutils
}  // namespace android
