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

#include <elfutils/writer.h>
#include <getopt.h>
#include <libgen.h>
#include <stdlib.h>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <string>

using ::android::elfutils::Elf32_File;
using ::android::elfutils::Elf64_File;
using ::android::elfutils::ElfFile;
using ::android::elfutils::ElfWriter;

template <typename ElfFile_t>
class InvalidElfFile : public ElfFile_t {
  public:
    using ElfFile_t::getDynamicEntries;
    using ElfFile_t::setDynamicEntries;

    InvalidElfFile(const ElfFile_t& other) : ElfFile_t(other.getPath()) {
        this->mEhdr = other.getEhdr();
        this->mPhdrs = other.getPhdrs();
        this->mShdrs = other.getShdrs();
        this->mSections = other.getSections();
    }

    void makeInvalid_setRwxLoadSegments() {
        for (auto& phdr : this->mPhdrs) {
            if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X)) {
                phdr.p_flags |= PF_W;
            }
        }
    }

    void makeInvalid_setZeroShentsize() { this->mEhdr.e_shentsize = 0; }

    void makeInvalid_setZeroShstrndx() { this->mEhdr.e_shstrndx = 0; }

    bool makeInvalid_addTextrelsToFlags() {
        std::vector<typename ElfFile_t::Elf_Dyn> entries;
        if (!this->getDynamicEntries(entries)) return false;

        bool found = false;
        for (auto& entry : entries) {
            if (entry.d_tag == DT_FLAGS) {
                entry.d_un.d_val |= DF_TEXTREL;
                found = true;
                break;
            }
        }

        return found && this->setDynamicEntries(entries);
    }

    bool makeInvalid_addTextrelsToDyn() {
        std::vector<typename ElfFile_t::Elf_Dyn> entries;
        if (!this->getDynamicEntries(entries)) return false;

        bool found = false;
        for (auto& entry : entries) {
            if (entry.d_tag == DT_FLAGS) {
                entry.d_tag = DT_TEXTREL;
                found = true;
                break;
            }
        }

        return found && this->setDynamicEntries(entries);
    }

    void makeInvalid_setEmptyShdrTable() { this->mEhdr.e_shnum = 0; }

    void makeInvalid_setUnalignedShdrOffset() { this->mEhdr.e_shoff++; }

    void makeInvalid_setZeroShdrTableOffset() { this->mEhdr.e_shoff = 0; }

    void makeInvalid_setZeroShdrTableContent() {
        for (auto& shdr : this->mShdrs) {
            memset(&shdr, 0, sizeof(shdr));
        }
    }

    void makeInvalid_setLoadSegments_RW_RX_RW() {
        std::vector<decltype(this->mPhdrs.begin())> load_segments;
        for (auto it = this->mPhdrs.begin(); it != this->mPhdrs.end(); ++it) {
            if (it->p_type == PT_LOAD) {
                load_segments.push_back(it);
            }
        }

        if (load_segments.size() >= 3) {
            load_segments[0]->p_flags = PF_R | PF_W;
            load_segments[1]->p_flags = PF_R | PF_X;
            load_segments[2]->p_flags = PF_R | PF_W;
        }
    }

    void makeInvalid_setLoadSegments_RX_RW_RX() {
        std::vector<decltype(this->mPhdrs.begin())> load_segments;
        for (auto it = this->mPhdrs.begin(); it != this->mPhdrs.end(); ++it) {
            if (it->p_type == PT_LOAD) {
                load_segments.push_back(it);
            }
        }

        if (load_segments.size() >= 3) {
            load_segments[0]->p_flags = PF_R | PF_X;
            load_segments[1]->p_flags = PF_R | PF_W;
            load_segments[2]->p_flags = PF_R | PF_X;
        }
    }
};

enum class InvalidElfType {
    kRwxLoadSegment,
    kZeroShentsize,
    kZeroShstrndx,
    kTextrels,
    kTextrels2,
    kEmptyShdrTable,
    kUnalignedShdrOffset,
    kZeroShdrTableContent,
    kZeroShdrTableOffset,
    kLoadSegments_RW_RX_RW,
    kLoadSegments_RX_RW_RX,
};

static const std::map<std::string, InvalidElfType> kInvalidElfTypeMap = {
        {"rwx_load_segment", InvalidElfType::kRwxLoadSegment},
        {"zero_shentsize", InvalidElfType::kZeroShentsize},
        {"zero_shstrndx", InvalidElfType::kZeroShstrndx},
        {"textrels", InvalidElfType::kTextrels},
        {"textrels2", InvalidElfType::kTextrels2},
        {"empty_shdr_table", InvalidElfType::kEmptyShdrTable},
        {"unaligned_shdr_offset", InvalidElfType::kUnalignedShdrOffset},
        {"zero_shdr_table_content", InvalidElfType::kZeroShdrTableContent},
        {"zero_shdr_table_offset", InvalidElfType::kZeroShdrTableOffset},
        {"load_segments_rw_rx_rw", InvalidElfType::kLoadSegments_RW_RX_RW},
        {"load_segments_rx_rw_rx", InvalidElfType::kLoadSegments_RX_RW_RX},
};

std::optional<InvalidElfType> getInvalidElfType(const std::string& str) {
    auto it = kInvalidElfTypeMap.find(str);
    if (it != kInvalidElfTypeMap.end()) {
        return it->second;
    }
    return std::nullopt;
}

void usage(char* progname) {
    std::cout << "Usage: " << progname
              << " --ref-elf=<path> --invalid-type=<type> --output=<path>\n"
              << R"(
Options:
--ref-elf=<path>        ELF file to use as a reference. (Required)
--invalid-type=<type>   The type of invalid ELF to generate. (Required)
--output=<path>         Path to write the generated invalid ELF file. (Required)

Available invalid types:
)";
    for (const auto& [key, val] : kInvalidElfTypeMap) {
        std::cout << "  " << key << "\n";
    }
    std::cout << "\n";
}

template <typename InvalidElfFile_t>
void makeInvalid(InvalidElfFile_t& file, InvalidElfType type) {
    switch (type) {
        case InvalidElfType::kRwxLoadSegment:
            file.makeInvalid_setRwxLoadSegments();
            break;
        case InvalidElfType::kZeroShentsize:
            file.makeInvalid_setZeroShentsize();
            break;
        case InvalidElfType::kZeroShstrndx:
            file.makeInvalid_setZeroShstrndx();
            break;
        case InvalidElfType::kTextrels:
            file.makeInvalid_addTextrelsToFlags();
            break;
        case InvalidElfType::kTextrels2:
            file.makeInvalid_addTextrelsToDyn();
            break;
        case InvalidElfType::kEmptyShdrTable:
            file.makeInvalid_setEmptyShdrTable();
            break;
        case InvalidElfType::kUnalignedShdrOffset:
            file.makeInvalid_setUnalignedShdrOffset();
            break;
        case InvalidElfType::kZeroShdrTableOffset:
            file.makeInvalid_setZeroShdrTableOffset();
            break;
        case InvalidElfType::kZeroShdrTableContent:
            file.makeInvalid_setZeroShdrTableContent();
            break;
        case InvalidElfType::kLoadSegments_RW_RX_RW:
            file.makeInvalid_setLoadSegments_RW_RX_RW();
            break;
        case InvalidElfType::kLoadSegments_RX_RW_RX:
            file.makeInvalid_setLoadSegments_RX_RW_RX();
            break;
    }
}

// For "unsafe" modifications that corrupt header offsets, this function handles
// the entire process: it captures the original valid offsets, applies the
// modification, and then writes the file out piece-by-piece using the saved
// offsets for seeking.
template <typename InvalidElfFile_t>
bool writeUnsafeModification(InvalidElfFile_t& file, const std::string& outputPath,
                             InvalidElfType type) {
    // 1. Capture the original, valid header info for seeking.
    const auto originalEhdr = file.getEhdr();
    const auto originalShdrs = file.getShdrs();

    std::vector<uint64_t> originalShdrOffsets;
    for (const auto& shdr : originalShdrs) {
        originalShdrOffsets.push_back(shdr.sh_offset);
    }

    // 2. Apply the invalidating modification to the in-memory object.
    makeInvalid(file, type);

    // 3. Manually write the file.
    ElfWriter<InvalidElfFile_t> writer(file, outputPath);

    // Write the (now modified) executable header.
    if (!writer.writeElfHeader(0)) {
        return false;
    }

    // Write (now modified) program headers using the original, valid program header offset.
    if (!writer.writeProgramHeaders(originalEhdr.e_phoff)) {
        return false;
    }

    // Write the (now modified) section headers using the original, valid section header offset.
    if (!writer.writeSectionHeaders(originalEhdr.e_shoff)) {
        return false;
    }

    // Write section data using the original, valid section header offsets.
    if (!writer.writeSections(originalShdrOffsets)) {
        return false;
    }

    return true;
}

int main(int argc, char* argv[]) {
    std::string refElfPath;
    std::string invalidTypeStr;
    std::string outputPath;

    static struct option longOptions[] = {{"ref-elf", required_argument, 0, 'r'},
                                          {"invalid-type", required_argument, 0, 'i'},
                                          {"output", required_argument, 0, 'o'},
                                          {0, 0, 0, 0}};

    int opt;
    while ((opt = getopt_long(argc, argv, "r:i:o:", longOptions, nullptr)) != -1) {
        switch (opt) {
            case 'r':
                refElfPath = optarg;
                break;
            case 'i':
                invalidTypeStr = optarg;
                break;
            case 'o':
                outputPath = optarg;
                break;
            case '?':
                usage(basename(argv[0]));
                return EXIT_FAILURE;
            default:
                abort();
        }
    }

    if (refElfPath.empty() || invalidTypeStr.empty() || outputPath.empty()) {
        std::cerr << "Error: --ref-elf, --invalid-type, and --output are required." << "\n";
        usage(basename(argv[0]));
        return EXIT_FAILURE;
    }

    auto invalidTypeOpt = getInvalidElfType(invalidTypeStr);
    if (!invalidTypeOpt) {
        std::cerr << "Error: Unknown invalid type '" << invalidTypeStr << "'." << "\n";
        usage(basename(argv[0]));
        return EXIT_FAILURE;
    }

    auto elfFile = ElfFile::create(refElfPath);
    if (!elfFile) {
        std::cerr << "Error: Could not open or parse reference ELF file: " << refElfPath << "\n";
        return EXIT_FAILURE;
    }

    bool success = false;
    if (elfFile->is32Bit()) {
        InvalidElfFile<Elf32_File> invalidFile(static_cast<Elf32_File&>(*elfFile));
        success = writeUnsafeModification(invalidFile, outputPath, *invalidTypeOpt);
    } else if (elfFile->is64Bit()) {
        InvalidElfFile<Elf64_File> invalidFile(static_cast<Elf64_File&>(*elfFile));
        success = writeUnsafeModification(invalidFile, outputPath, *invalidTypeOpt);
    }

    if (!success) {
        std::cerr << "Error: Failed to write invalid ELF to " << outputPath << "\n";
        return EXIT_FAILURE;
    }

    std::cout << "Successfully generated invalid ELF: " << outputPath << "\n";
    return EXIT_SUCCESS;
}
