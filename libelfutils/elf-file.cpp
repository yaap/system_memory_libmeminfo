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

#include <elfutils/elf-file.h>
#include <elfutils/parse.h>

#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace android {
namespace elfutils {

std::unique_ptr<ElfFile> ElfFile::createFromIdent(const std::string& path) {
    std::ifstream elfStream(path, std::ios::binary);
    if (!elfStream) {
        return {};
    }

    // Read the ELF identity.
    // See: https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/elf.h#L334
    char elfIdent[EI_NIDENT];
    elfStream.read(elfIdent, EI_NIDENT);
    if (elfStream.gcount() != EI_NIDENT) {
        return {};
    }

    // Check the magic number.
    if (elfIdent[EI_MAG0] != ELFMAG0 || elfIdent[EI_MAG1] != ELFMAG1 ||
        elfIdent[EI_MAG2] != ELFMAG2 || elfIdent[EI_MAG3] != ELFMAG3) {
        return {};
    }

    // Check for 32/64 bit.
    char classNum = elfIdent[EI_CLASS];
    if (classNum == ELFCLASS32) {
        return std::make_unique<Elf32_File>(path);
    } else if (classNum == ELFCLASS64) {
        return std::make_unique<Elf64_File>(path);
    }

    return {};
}

std::unique_ptr<ElfFile> ElfFile::create(const std::string& path) {
    auto elfFile = createFromIdent(path);
    if (!elfFile) {
        return {};
    }

    if (elfFile->is32Bit()) {
        ElfParser<Elf32_File> parser(*static_cast<Elf32_File*>(elfFile.get()));
        if (!parser.parse()) {
            return {};
        }
    } else {
        ElfParser<Elf64_File> parser(*static_cast<Elf64_File*>(elfFile.get()));
        if (!parser.parse()) {
            return {};
        }
    }

    return elfFile;
}

template <typename Ehdr_t, typename Phdr_t, typename Shdr_t, typename Dyn_t>
bool ElfFileImpl<Ehdr_t, Phdr_t, Shdr_t, Dyn_t>::getDynamicEntries(
        std::vector<Elf_Dyn>& entries) const {
    for (size_t i = 0; i < mShdrs.size(); ++i) {
        if (mShdrs[i].sh_type == SHT_DYNAMIC) {
            const auto& dynamicSection = mSections[i];

            const Elf_Dyn* dyn = reinterpret_cast<const Elf_Dyn*>(dynamicSection.data.data());
            size_t count = dynamicSection.size / sizeof(Elf_Dyn);

            entries.assign(dyn, dyn + count);

            return true;
        }
    }
    return false;
}

template <typename Ehdr_t, typename Phdr_t, typename Shdr_t, typename Dyn_t>
bool ElfFileImpl<Ehdr_t, Phdr_t, Shdr_t, Dyn_t>::setDynamicEntries(
        const std::vector<Elf_Dyn>& entries) {
    for (size_t i = 0; i < mShdrs.size(); ++i) {
        if (mShdrs[i].sh_type == SHT_DYNAMIC) {
            auto& dynamicSection = mSections[i];

            dynamicSection.size = entries.size() * sizeof(Elf_Dyn);
            dynamicSection.data.resize(dynamicSection.size);

            memcpy(dynamicSection.data.data(), entries.data(), dynamicSection.size);

            mShdrs[i].sh_size = dynamicSection.size;

            return true;
        }
    }
    return false;
}

template <typename Ehdr_t, typename Phdr_t, typename Shdr_t, typename Dyn_t>
bool ElfFileImpl<Ehdr_t, Phdr_t, Shdr_t, Dyn_t>::parseProgramHeaders() {
    ElfParser<ElfFileImpl<Ehdr_t, Phdr_t, Shdr_t, Dyn_t>> parser(*this);
    return parser.parseExecutableHeader() && parser.parseProgramHeaders();
}

template <typename Ehdr_t, typename Phdr_t, typename Shdr_t, typename Dyn_t>
bool ElfFileImpl<Ehdr_t, Phdr_t, Shdr_t, Dyn_t>::parseSections() {
    ElfParser<ElfFileImpl<Ehdr_t, Phdr_t, Shdr_t, Dyn_t>> parser(*this);
    return parser.parseExecutableHeader() && parser.parseSectionHeaders() && parser.parseSections();
}

/*
 * Returns the minimum of all PT_LOAD segments' p_align.
 */
template <typename Ehdr_t, typename Phdr_t, typename Shdr_t, typename Dyn_t>
std::optional<int64_t> ElfFileImpl<Ehdr_t, Phdr_t, Shdr_t, Dyn_t>::getMinLoadSegmentAlignment()
        const {
    std::optional<int64_t> minAlign;

    for (const auto& phdr : mPhdrs) {
        if (phdr.p_type != PT_LOAD) {
            continue;
        }

        int64_t align = phdr.p_align;
        if (!minAlign.has_value() || align < *minAlign) {
            minAlign = align;
        }
    }

    return minAlign;
}

// Explicitly instantiate the templates for 32-bit and 64-bit ELF files.
template class ElfFileImpl<Elf32_Ehdr, Elf32_Phdr, Elf32_Shdr, Elf32_Dyn>;
template class ElfFileImpl<Elf64_Ehdr, Elf64_Phdr, Elf64_Shdr, Elf64_Dyn>;

}  // namespace elfutils
}  // namespace android
