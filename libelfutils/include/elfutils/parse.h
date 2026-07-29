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

#include <android-base/logging.h>
#include <elfutils/elf-file.h>

#include <filesystem>
#include <fstream>
#include <optional>

namespace android {
namespace elfutils {

/*
 * Class to parse ELF binaries.
 *
 * The class will parse the 4 parts if present
 *
 * - Executable header (Elf64_Ehdr or Elf32_Ehdr).
 * - Program headers (Elf64_Phdr or Elf32_Phdr - present in executables or shared libraries).
 * - Section headers (Elf64_Shdr or Elf32_Shdr)
 * - Sections (.interp, .init, .plt, .text, .rodata, .data, .bss, .shstrtab, etc).
 *
 * The parser is used internally by ElfFile::create() to populate its fields.
 */
template <typename ElfFile_t>
class ElfParser {
  public:
    explicit ElfParser(ElfFile_t& elfFile)
        : mElfFile(elfFile), mElfStream(mElfFile.getPath(), std::ios::binary) {
        std::error_code ec;
        mFileSize = std::filesystem::file_size(mElfFile.getPath(), ec);
        if (ec) {
            mFileSize = 0;
        }
    }

    ~ElfParser() = default;

    [[nodiscard]] bool parse() {
        return parseExecutableHeader() && parseProgramHeaders() && parseSectionHeaders() &&
               parseSections();
    }

    using Elf_Ehdr = typename ElfFile_t::Elf_Ehdr;
    using Elf_Phdr = typename ElfFile_t::Elf_Phdr;
    using Elf_Shdr = typename ElfFile_t::Elf_Shdr;
    using Elf_Dyn = typename ElfFile_t::Elf_Dyn;

    bool parseExecutableHeader() {
        if (mParsedExecutableHeader) return true;

        if (!mElfStream) {
            return false;
        }

        mElfStream.seekg(0);
        mElfStream.read((char*)&mElfFile.mEhdr, sizeof(mElfFile.mEhdr));

        mParsedExecutableHeader = (mElfStream.gcount() == sizeof(mElfFile.mEhdr));
        return mParsedExecutableHeader;
    }

    bool parseProgramHeaders() {
        if (mParsedProgramHeaders) return true;

        uint64_t phOffset = mElfFile.mEhdr.e_phoff;
        uint16_t phNum = mElfFile.mEhdr.e_phnum;

        if (!mElfStream) {
            return false;
        }

        if (phNum == 0) {
            mParsedProgramHeaders = true;
            return true;
        }

        uint64_t phEnd;
        if (__builtin_add_overflow(phOffset, static_cast<uint64_t>(phNum) * sizeof(Elf_Phdr),
                                   &phEnd) ||
            phEnd > static_cast<uint64_t>(mFileSize)) {
            return false;
        }

        mElfStream.seekg(phOffset);
        for (int i = 0; i < phNum; i++) {
            Elf_Phdr phdr;

            mElfStream.read((char*)&phdr, sizeof(phdr));
            if (mElfStream.gcount() != sizeof(phdr)) {
                return false;
            }

            mElfFile.mPhdrs.push_back(phdr);
        }

        mParsedProgramHeaders = true;
        return mParsedProgramHeaders;
    }

    bool parseSectionHeaders() {
        if (mParsedSectionHeaders) return true;

        uint64_t shOffset = mElfFile.mEhdr.e_shoff;
        uint16_t shNum = mElfFile.mEhdr.e_shnum;

        if (!mElfStream) {
            return false;
        }

        if (shNum == 0) {
            mParsedSectionHeaders = true;
            return true;
        }

        uint64_t shEnd;
        if (__builtin_add_overflow(shOffset, static_cast<uint64_t>(shNum) * sizeof(Elf_Shdr),
                                   &shEnd) ||
            shEnd > static_cast<uint64_t>(mFileSize)) {
            return false;
        }

        mElfStream.seekg(shOffset);
        for (int i = 0; i < shNum; i++) {
            Elf_Shdr shdr;

            mElfStream.read((char*)&shdr, sizeof(shdr));
            if (mElfStream.gcount() != sizeof(shdr)) {
                return false;
            }

            mElfFile.mShdrs.push_back(shdr);
        }

        mParsedSectionHeaders = true;
        return mParsedSectionHeaders;
    }

    bool parseSections() {
        if (mParsedSections) return true;

        bool allSectionsParsedOk = true;
        // First, attempt to parse all section data.
        for (size_t i = 0; i < mElfFile.mShdrs.size(); i++) {
            // Pre-initialize the section. If parseSectionData fails, this ensures
            // that a valid but empty section is added, maintaining correct indexing.
            Elf_Sc section = {.size = 0, .index = static_cast<uint16_t>(i)};
            if (!parseSectionData(i, section)) {
                allSectionsParsedOk = false;
            }
            mElfFile.mSections.push_back(section);
        }

        // Find the string table section. Even if it's invalid, we'll try to parse names.
        // The parseSectionName function is safe against corrupted tables.
        if (mElfFile.mEhdr.e_shstrndx < mElfFile.mSections.size()) {
            const Elf_Sc& strTbl = mElfFile.mSections[mElfFile.mEhdr.e_shstrndx];
            // Then, parse all section names.
            for (auto& section : mElfFile.mSections) {
                parseSectionName(section, strTbl);
            }
        }

        mParsedSections = allSectionsParsedOk;
        return mParsedSections;
    }

  private:
    ElfFile_t& mElfFile;
    std::ifstream mElfStream;
    uintmax_t mFileSize;
    bool mParsedExecutableHeader = false;
    bool mParsedProgramHeaders = false;
    bool mParsedSectionHeaders = false;
    bool mParsedSections = false;

    bool parseSectionData(size_t index, Elf_Sc& section) {
        if (!mElfStream) {
            return false;
        }

        const auto& shdr = mElfFile.mShdrs[index];
        uint64_t sOffset = shdr.sh_offset;
        uint64_t sSize = shdr.sh_size;
        uint32_t sType = shdr.sh_type;

        if (sType != SHT_NOBITS) {
            uint64_t sEnd;
            if (__builtin_add_overflow(sOffset, sSize, &sEnd) ||
                sEnd > static_cast<uint64_t>(mFileSize)) {
                return false;
            }

            section.data.resize(sSize);
            mElfStream.seekg(sOffset);

            mElfStream.read(section.data.data(), sSize);
            if (mElfStream.gcount() != static_cast<std::streamsize>(sSize)) {
                return false;
            }
        }

        // NOTE: We don't populate section.data for the SHT_NOBITS sections
        // as these are not present on the file, and only become relevant
        // after the ELF is loaded into memory.

        section.size = sSize;
        section.index = index;

        return true;
    }

    void parseSectionName(Elf_Sc& section, const Elf_Sc& strTbl) {
        section.name = "";  // Default name

        if (strTbl.data.empty()) return;

        const Elf_Shdr& shdr = mElfFile.mShdrs[section.index];
        uint32_t nameIdx = shdr.sh_name;
        const char* st = strTbl.data.data();

        if (nameIdx >= strTbl.size) return;

        if (memchr(&st[nameIdx], 0, strTbl.size - nameIdx) == nullptr) return;

        section.name = &st[nameIdx];
    }
};

}  // namespace elfutils
}  // namespace android
