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

#include <elfutils/comparator.h>

#include <elfutils/elf-file.h>

#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <elf.h>

namespace android {
namespace elfutils {

namespace {

void printEhdrDiff(const std::string& name, unsigned long long hdrField1,
                   unsigned long long hdrField2) {
    std::cout << "\tDiff ehdr1." << name << " = 0x" << std::hex << hdrField1 << " != "
              << "ehdr2." << name << " = 0x" << std::hex << hdrField2 << "\n";
}

void printFieldDiff(const std::string& strPrefix, const std::string& fieldName, int index,
                    unsigned long long shdrField1, unsigned long long shdrField2) {
    std::cout << "\tDiff " << strPrefix << "1[" << index << "]." << fieldName << " = 0x" << std::hex
              << shdrField1 << " != " << strPrefix << "2[" << index << "]." << fieldName << " = 0x"
              << std::hex << shdrField2 << "\n";
}

}  // namespace

template <typename ElfFile_t>
class ElfComparatorImpl : public ElfComparator {
  public:
    ElfComparatorImpl(ElfFile_t& file1, ElfFile_t& file2) : mFile1(file1), mFile2(file2) {}

    bool compareHeaders() { return compare(mFile1.getEhdr(), mFile2.getEhdr()); }

    bool compareProgramHeaders() { return compare(mFile1.getPhdrs(), mFile2.getPhdrs()); }

    bool compareSectionHeaders() { return compare(mFile1.getShdrs(), mFile2.getShdrs()); }

    bool compareSections() { return compare(mFile1.getSections(), mFile2.getSections()); }

  private:
    const ElfFile_t& mFile1;
    const ElfFile_t& mFile2;

    using Elf_Ehdr = typename ElfFile_t::Elf_Ehdr;
    using Elf_Phdr = typename ElfFile_t::Elf_Phdr;
    using Elf_Shdr = typename ElfFile_t::Elf_Shdr;
    using Elf_Dyn = typename ElfFile_t::Elf_Dyn;

    bool compare(const Elf_Ehdr& ehdr1, const Elf_Ehdr& ehdr2) {
        bool equal = true;

        std::cout << "\nComparing ELF Executable Headers ..." << "\n";

        // Comparing magic number and other info.
        for (int i = 0; i < EI_NIDENT; i++) {
            if (ehdr1.e_ident[i] != ehdr2.e_ident[i]) {
                std::cout << "Diff ehdr1.e_ident[" << std::dec << i << "]=" << ehdr1.e_ident[i]
                          << " != "
                          << "ehdr2.e_ident[" << i << "]=" << ehdr2.e_ident[i] << "\n";
                equal = false;
            }
        }

        if (ehdr1.e_type != ehdr2.e_type) {
            printEhdrDiff("e_type", ehdr1.e_type, ehdr2.e_type);
            equal = false;
        }

        if (ehdr1.e_machine != ehdr2.e_machine) {
            printEhdrDiff("e_machine", ehdr1.e_machine, ehdr2.e_machine);
            equal = false;
        }

        if (ehdr1.e_version != ehdr2.e_version) {
            printEhdrDiff("e_version", ehdr1.e_version, ehdr2.e_version);
            equal = false;
        }

        if (ehdr1.e_entry != ehdr2.e_entry) {
            printEhdrDiff("e_entry", ehdr1.e_entry, ehdr2.e_entry);
            equal = false;
        }

        if (ehdr1.e_phoff != ehdr2.e_phoff) {
            printEhdrDiff("e_phoff", ehdr1.e_phoff, ehdr2.e_phoff);
            equal = false;
        }

        if (ehdr1.e_shoff != ehdr2.e_shoff) {
            printEhdrDiff("e_shoff", ehdr1.e_shoff, ehdr2.e_shoff);
            equal = false;
        }

        if (ehdr1.e_flags != ehdr2.e_flags) {
            printEhdrDiff("e_flags", ehdr1.e_flags, ehdr2.e_flags);
            equal = false;
        }

        if (ehdr1.e_ehsize != ehdr2.e_ehsize) {
            printEhdrDiff("e_ehsize", ehdr1.e_ehsize, ehdr2.e_ehsize);
            equal = false;
        }

        if (ehdr1.e_phentsize != ehdr2.e_phentsize) {
            printEhdrDiff("e_phentsize", ehdr1.e_phentsize, ehdr2.e_phentsize);
            equal = false;
        }

        if (ehdr1.e_phnum != ehdr2.e_phnum) {
            printEhdrDiff("e_phnum", ehdr1.e_phnum, ehdr2.e_phnum);
            equal = false;
        }

        if (ehdr1.e_shentsize != ehdr2.e_shentsize) {
            printEhdrDiff("e_shentsize", ehdr1.e_shentsize, ehdr2.e_shentsize);
            equal = false;
        }

        if (ehdr1.e_shnum != ehdr2.e_shnum) {
            printEhdrDiff("e_shnum", ehdr1.e_shnum, ehdr2.e_shnum);
            equal = false;
        }

        if (ehdr1.e_shstrndx != ehdr2.e_shstrndx) {
            printEhdrDiff("e_shstrndx", ehdr1.e_shstrndx, ehdr2.e_shstrndx);
            equal = false;
        }

        return equal;
    }

    bool compare(const std::vector<Elf_Phdr>& phdrs1, const std::vector<Elf_Phdr>& phdrs2) {
        bool equal = true;

        std::cout << "\nComparing ELF Program Headers ..." << "\n";

        if (phdrs1.size() != phdrs2.size()) {
            std::cout << "\tDiff phdrs1.size() = " << std::dec << phdrs1.size() << " != "
                      << "phdrs2.size() = " << phdrs2.size() << "\n";
            return false;
        }

        for (size_t i = 0; i < phdrs1.size(); i++) {
            auto phdr1 = phdrs1[i];
            auto phdr2 = phdrs2[i];

            if (phdr1.p_type != phdr2.p_type) {
                printFieldDiff("phdrs", "p_type", i, phdr1.p_type, phdr2.p_type);
                equal = false;
            }

            if (phdr1.p_flags != phdr2.p_flags) {
                printFieldDiff("phdrs", "p_flags", i, phdr1.p_flags, phdr2.p_flags);
                equal = false;
            }

            if (phdr1.p_offset != phdr2.p_offset) {
                printFieldDiff("phdrs", "p_offset", i, phdr1.p_offset, phdr2.p_offset);
                equal = false;
            }

            if (phdr1.p_vaddr != phdr2.p_vaddr) {
                printFieldDiff("phdrs", "p_vaddr", i, phdr1.p_vaddr, phdr2.p_vaddr);
                equal = false;
            }

            if (phdr1.p_paddr != phdr2.p_paddr) {
                printFieldDiff("phdrs", "p_paddr", i, phdr1.p_paddr, phdr2.p_paddr);
                equal = false;
            }

            if (phdr1.p_filesz != phdr2.p_filesz) {
                printFieldDiff("phdrs", "p_filesz", i, phdr1.p_filesz, phdr2.p_filesz);
                equal = false;
            }

            if (phdr1.p_memsz != phdr2.p_memsz) {
                printFieldDiff("phdrs", "p_memsz", i, phdr1.p_memsz, phdr2.p_memsz);
                equal = false;
            }

            if (phdr1.p_align != phdr2.p_align) {
                printFieldDiff("phdrs", "p_align", i, phdr1.p_align, phdr2.p_align);
                equal = false;
            }
        }

        return equal;
    }

    bool compare(const std::vector<Elf_Shdr>& shdrs1, const std::vector<Elf_Shdr>& shdrs2) {
        bool equal = true;

        std::cout << "\nComparing ELF Section Headers ..." << "\n";

        if (shdrs1.size() != shdrs2.size()) {
            std::cout << "\tDiff shdrs1.size() = " << std::dec << shdrs1.size() << " != "
                      << "shdrs2.size() = " << shdrs2.size() << "\n";
            return false;
        }

        for (size_t i = 0; i < shdrs1.size(); i++) {
            auto shdr1 = shdrs1[i];
            auto shdr2 = shdrs2[i];

            if (shdr1.sh_name != shdr2.sh_name) {
                printFieldDiff("shdrs", "sh_name", i, shdr1.sh_name, shdr2.sh_name);
                equal = false;
            }

            if (shdr1.sh_type != shdr2.sh_type) {
                printFieldDiff("shdrs", "sh_type", i, shdr1.sh_type, shdr2.sh_type);
                equal = false;
            }

            if (shdr1.sh_flags != shdr2.sh_flags) {
                printFieldDiff("shdrs", "sh_flags", i, shdr1.sh_flags, shdr2.sh_flags);
                equal = false;
            }

            if (shdr1.sh_addr != shdr2.sh_addr) {
                printFieldDiff("shdrs", "sh_addr", i, shdr1.sh_addr, shdr2.sh_addr);
                equal = false;
            }

            if (shdr1.sh_offset != shdr2.sh_offset) {
                printFieldDiff("shdrs", "sh_offset", i, shdr1.sh_offset, shdr2.sh_offset);
                equal = false;
            }

            if (shdr1.sh_size != shdr2.sh_size) {
                printFieldDiff("shdrs", "sh_size", i, shdr1.sh_size, shdr2.sh_size);
                equal = false;
            }

            if (shdr1.sh_link != shdr2.sh_link) {
                printFieldDiff("shdrs", "sh_link", i, shdr1.sh_link, shdr2.sh_link);
                equal = false;
            }

            if (shdr1.sh_info != shdr2.sh_info) {
                printFieldDiff("shdrs", "sh_info", i, shdr1.sh_info, shdr2.sh_info);
                equal = false;
            }

            if (shdr1.sh_addralign != shdr2.sh_addralign) {
                printFieldDiff("shdrs", "sh_addralign", i, shdr1.sh_addralign, shdr2.sh_addralign);
                equal = false;
            }

            if (shdr1.sh_entsize != shdr2.sh_entsize) {
                printFieldDiff("shdrs", "sh_entsize", i, shdr1.sh_entsize, shdr2.sh_entsize);
                equal = false;
            }
        }

        return equal;
    }

    bool compare(const std::vector<Elf_Sc>& sections1, const std::vector<Elf_Sc>& sections2) {
        bool equal = true;

        std::cout << "\nComparing ELF Sections (content) ..." << "\n";

        if (sections1.size() != sections2.size()) {
            std::cout << "\tDiff sections1.size() = " << std::dec << sections1.size() << " != "
                      << "sections2.size() = " << sections2.size() << "\n";
            return false;
        }

        for (size_t i = 0; i < sections1.size(); i++) {
            if (sections1[i].size != sections2[i].size) {
                std::cout << "\tDiff sections1[" << std::dec << i
                          << "].size = " << sections1[i].size << " != "
                          << "sections2[" << i << "].size = " << sections2[i].size << "\n";
                equal = false;
                // If size is different, data is not compared.
                continue;
            }

            if (sections1[i].data.empty() && sections2[i].data.empty()) {
                // The .bss section is empty.
                continue;
            }

            if (sections1[i].data.empty() || sections2[i].data.empty()) {
                // The index of the .bss section is different for both files.
                equal = false;
                continue;
            }

            if (sections1[i].data != sections2[i].data) {
                std::cout << "\tDiff " << std::dec << "section1[" << i << "].data != "
                          << "section2[" << i << "].data" << "\n";

                equal = false;
            }
        }

        return equal;
    }
};

std::unique_ptr<ElfComparator> ElfComparator::create(ElfFile& file1, ElfFile& file2) {
    using Elf64_Comparator = ElfComparatorImpl<Elf64_File>;
    using Elf32_Comparator = ElfComparatorImpl<Elf32_File>;

    if (file1.is64Bit() && file2.is64Bit()) {
        return std::make_unique<Elf64_Comparator>(static_cast<Elf64_File&>(file1),
                                                  static_cast<Elf64_File&>(file2));
    } else if (file1.is32Bit() && file2.is32Bit()) {
        return std::make_unique<Elf32_Comparator>(static_cast<Elf32_File&>(file1),
                                                  static_cast<Elf32_File&>(file2));
    }

    return {};
}

}  // namespace elfutils
}  // namespace android
