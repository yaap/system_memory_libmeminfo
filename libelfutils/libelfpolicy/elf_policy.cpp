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

#include <algorithm>
#include <iomanip>
#include <sstream>

#include <elfutils/elf-file.h>

#include "elfpolicy/elf_policy.h"

namespace android {
namespace elfpolicy {

using ::android::elfutils::Elf64_File;
using ::android::elfutils::ElfFile;

static inline std::string to_hex_string(uint64_t value) {
    std::stringstream ss;
    ss << std::hex << value;  // Converts to hex
    return ss.str();
}

bool VerifyLoadSegmentsAlignment(const ElfFile& elfFile, uint64_t pageSize, std::string& errorMsg) {
    if (elfFile.is32Bit()) {
        // 32-bit files are not subject to the 16k alignment requirement.
        // Consider them compatible by default.
        return true;
    }

    auto minAlign = elfFile.getMinLoadSegmentAlignment();

    // This case means there were no loadable segments, which is unusual
    // but not a failure of the alignment check itself. We can consider it passing.
    if (!minAlign) return true;

    if (*minAlign < pageSize) {
        errorMsg = "Minimum ELF LOAD segment alignment: 0x" + to_hex_string(*minAlign)
                  + " is not at least 0x" + to_hex_string(pageSize) + " aligned.";
        return false;
    }

    return true;
}

/*
 * Returns the containing LOAD segment of the RELRO if found,
 * else nullptr.
 */
static inline const Elf64_Phdr* RelroLoadSegment(const Elf64_File& elf64File,
                                                 const Elf64_Phdr& relroPhdr) {
    auto& phdrs = elf64File.getPhdrs();

    // Create a sorted list of LOAD segments to find the correct container.
    std::vector<const Elf64_Phdr*> loadSegments;
    for (const auto& phdr : phdrs) {
        if (phdr.p_type == PT_LOAD) {
            loadSegments.push_back(&phdr);
        }
    }

    std::sort(loadSegments.begin(), loadSegments.end(),
              [](const Elf64_Phdr* a, const Elf64_Phdr* b) { return a->p_vaddr < b->p_vaddr; });

    for (size_t i = 0; i < loadSegments.size(); ++i) {
        const auto* current_load = loadSegments[i];
        uint64_t next_load_vaddr = UINT64_MAX;
        if (i + 1 < loadSegments.size()) {
            next_load_vaddr = loadSegments[i + 1]->p_vaddr;
        }

        auto relro_start = relroPhdr.p_vaddr;
        auto relro_end = relro_start + relroPhdr.p_memsz;

        if (relro_start >= current_load->p_vaddr && relro_end <= next_load_vaddr) {
            return current_load;
        }
    }

    return nullptr;
}

/*
 * Returns true if RELRO is the only thing contained in the LOAD segment,
 * else false.
 */
static inline bool RelroIsEntireLoadSegment(const Elf64_File& elf64File,
                                            const Elf64_Phdr& relroPhdr,
                                            const Elf64_Phdr& loadPhdr) {
    const auto& shdrs = elf64File.getShdrs();

    auto getContainedSections = [&](const Elf64_Phdr& segment) {
        std::vector<Elf64_Shdr> contained;
        for (const auto& shdr : shdrs) {
            if (shdr.sh_addr >= segment.p_vaddr &&
                (shdr.sh_addr + shdr.sh_size) <= (segment.p_vaddr + segment.p_memsz)) {
                contained.push_back(shdr);
            }
        }
        return contained;
    };

    auto relroSections = getContainedSections(relroPhdr);
    auto loadSections = getContainedSections(loadPhdr);

    auto shdrSorter = [](const Elf64_Shdr& a, const Elf64_Shdr& b) {
        return a.sh_addr < b.sh_addr;
    };

    std::sort(relroSections.begin(), relroSections.end(), shdrSorter);
    std::sort(loadSections.begin(), loadSections.end(), shdrSorter);

    bool sameSections = relroSections.size() == loadSections.size();

    if (!sameSections) return false;

    for (size_t i = 0; i < relroSections.size(); ++i) {
        const auto& relroShdr = relroSections[i];
        const auto& loadShdr = loadSections[i];
        if (memcmp(&relroShdr, &loadShdr, sizeof(Elf64_Shdr)) != 0) {
            return false;
        }
    }

    return true;
}

/*
 * Returns true is RELRO's start is correctly aligned, false otherwise.
 */
static inline bool RelroStartIsValid(const Elf64_Phdr& relroPhdr, const Elf64_Phdr& loadPhdr,
                                     uint64_t pageSize) {
    auto relroStart = relroPhdr.p_vaddr;
    auto loadStart = loadPhdr.p_vaddr;

    return (relroStart % pageSize == 0) || (relroStart == loadStart);
}

/*
 * Returns true is RELRO's end is correctly aligned, false otherwise.
 */
static inline bool RelroEndIsValid(const Elf64_Phdr& relroPhdr, const Elf64_Phdr& loadPhdr,
                                   uint64_t pageSize) {
    auto relroStart = relroPhdr.p_vaddr;
    auto loadStart = loadPhdr.p_vaddr;
    auto relroEnd = relroStart + relroPhdr.p_memsz;
    auto loadEnd = loadStart + loadPhdr.p_memsz;

    return (relroEnd % pageSize == 0) || (relroEnd == loadEnd);
}

/*
 * The cases we need to consider for RELRO validation are:
 *   1. If the RELRO section is the only section in the containing LOAD segment,
 *      the it doesn't need to follow any particular alignment as it's
 *      alignment is ultimately guaranteed by the containing LOAD segment.
 *   2. If the RELRO is the prefix of a LOAD segment, its END address must be
 *      PAGE-aligned.
 *   3. If the RELRO is the suffix of a LOAD segment, its START address must
 *      be PAGE-aligned.
 *   4. If the RELRO is neither a prefix nor a suffix of the containing LOAD
 *      segment and is not the only section in the LOAD segment; both its
 *      START and END addresses must be PAGE-aligned.
 */
static bool VerifyRelroSegment(const Elf64_File& elf64File, const Elf64_Phdr& relroPhdr,
                               uint64_t pageSize, std::string& errorMsg) {
    if (relroPhdr.p_memsz == 0) {
        errorMsg = "RELRO segment's mem size cannot be zero.";
        return false;
    }

    const Elf64_Phdr* loadPhdr = RelroLoadSegment(elf64File, relroPhdr);

    if (!loadPhdr) {
        errorMsg =
                "RELRO not contained within any LOAD segment. Skipping check (likely obfuscated).";
        // This is not a hard failure, but a warning. Return true.
        return true;
    }

    if (loadPhdr->p_memsz == 0) {
        errorMsg = "RELRO segment's corresponding LOAD segment mem size cannot be zero.";
        return false;
    }

    // If sections are the same, RELRO is the entire LOAD segment and alignment is guaranteed.
    bool relroIsEntireLoadSegment = RelroIsEntireLoadSegment(elf64File, relroPhdr, *loadPhdr);
    if (relroIsEntireLoadSegment) return true;

    if (!RelroStartIsValid(relroPhdr, *loadPhdr, pageSize)) {
        errorMsg = "RELRO is not a prefix and its start is not at least PAGE-aligned (0x" +
                   to_hex_string(pageSize) + ").";
        return false;
    }

    if (!RelroEndIsValid(relroPhdr, *loadPhdr, pageSize)) {
        errorMsg = "RELRO is not a suffix and its end is not at least PAGE-aligned (0x" +
                   to_hex_string(pageSize) + ").";
        return false;
    }

    return true;
}

bool VerifyRelroSegments(const ElfFile& elfFile, uint64_t pageSize, std::string& errorMsg) {
    if (elfFile.is32Bit()) {
        // RELRO segment checks are only for 64-bit files.
        return true;
    }

    const auto& elf64File = static_cast<const Elf64_File&>(elfFile);
    const auto& phdrs = elf64File.getPhdrs();

    for (const auto& phdr : phdrs) {
        if (phdr.p_type != PT_GNU_RELRO) continue;
        if (!VerifyRelroSegment(elf64File, phdr, pageSize, errorMsg)) return false;
    }

    return true;
}

}  // namespace elfpolicy
}  // namespace android
