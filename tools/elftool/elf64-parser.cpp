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

#include "elf64-parser.h"

#include <elf.h>
#include <stdlib.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "elf64-binary.h"

using namespace std;

namespace lib {
namespace elf {

// Parse the elf file and populate the elfBinary object.
void Elf64Parser::ParseElfFile(std::string& fileName, Elf64Binary& elf64Binary) {
    std::cout << "Parsing ELF file " << fileName << endl;
    std::ifstream elfFile;

    OpenElfFile(fileName, elfFile);

    ParseExecutableHeader(elfFile, elf64Binary);
    ParseProgramHeaders(elfFile, elf64Binary);
    ParseSectionHeaders(elfFile, elf64Binary);
    ParseSections(elfFile, elf64Binary);

    CloseElfFile(elfFile);
}

void Elf64Parser::OpenElfFile(std::string& fileName, std::ifstream& elfFile) {
    elfFile.open(fileName.c_str(), std::ifstream::in);

    if (!elfFile.is_open()) {
        std::cerr << "Failed to open the file: " << fileName << endl;
        exit(-1);
    }
}

void Elf64Parser::CloseElfFile(std::ifstream& elfFile) {
    if (elfFile.is_open()) {
        elfFile.close();
    }
}

// Parse the executable header.
//
// Note: The command below can be used to print the executable header:
//
//  $ readelf -h ../a.out
void Elf64Parser::ParseExecutableHeader(std::ifstream& elfFile, Elf64Binary& elf64Binary) {
    std::cout << "Parsing Executable ELF64 Header" << std::endl;

    // Move the cursor position to the very beginning.
    elfFile.seekg(0);
    elfFile.read((char*)&elf64Binary.ehdr, sizeof(elf64Binary.ehdr));

    if (!elfFile.good()) {
        std::cerr << "Failed to read the executable header" << std::endl;
        exit(-1);
    }
}

// Parse the Program or Segment Headers.
//
// Note: The command below can be used to print the program headers:
//
//  $ readelf --program-headers ./example_4k
//  $ readelf -l ./example_4k
void Elf64Parser::ParseProgramHeaders(std::ifstream& elfFile, Elf64Binary& elf64Binary) {
    uint64_t phOffset = elf64Binary.ehdr.e_phoff;
    uint16_t phNum = elf64Binary.ehdr.e_phnum;

    std::cout << "Parsing Program Headers" << std::endl;

    // Move the cursor position to the program header offset.
    elfFile.seekg(phOffset);

    for (int i = 0; i < phNum; i++) {
        Elf64_Phdr* phdrPtr = new Elf64_Phdr;

        elfFile.read((char*)phdrPtr, sizeof(*phdrPtr));
        if (!elfFile.good()) {
            std::cerr << "Failed to read program header [" << i << "]" << std::endl;
            exit(-1);
        }

        elf64Binary.phdrs.push_back(phdrPtr);
    }
}

void Elf64Parser::ParseSections(std::ifstream& elfFile, Elf64Binary& elf64Binary) {
    std::cout << "Parsing Sections" << std::endl;

    Elf64_Sc* sStrTblPtr;
    // Parse sections after reading all the section headers.
    for (int i = 0; i < elf64Binary.shdrs.size(); i++) {
        Elf64_Shdr* shdrPtr = elf64Binary.shdrs[i];
        uint64_t sOffset = shdrPtr->sh_offset;
        uint64_t sSize = shdrPtr->sh_size;

        Elf64_Sc* sPtr = new Elf64_Sc;
        uint8_t* data = NULL;

        // Skip .bss section.
        if (shdrPtr->sh_type != SHT_NOBITS) {
            data = new uint8_t[sSize];

            // Move the cursor position to the section offset.
            elfFile.seekg(sOffset);
            elfFile.read((char*)data, sSize);
            if (!elfFile.good()) {
                std::cerr << "Failed to read section [" << i << "]"
                          << " with offset " << std::hex << sOffset << " and size " << std::dec
                          << sSize << std::endl;
                exit(-1);
            }
        }

        sPtr->data = data;
        sPtr->size = sSize;
        sPtr->index = i;

        // If string table section, parse the section names.
        // The index of the string table is in the executable header.
        if (elf64Binary.ehdr.e_shstrndx == i) {
            sStrTblPtr = sPtr;
            ParseStringTableSection(elf64Binary, sPtr);
        }

        elf64Binary.sections.push_back(sPtr);
    }

    // Set the data section name.
    // This is done after reading the data section with index e_shstrndx.
    for (int i = 0; i < elf64Binary.sections.size(); i++) {
        Elf64_Sc* sPtr = elf64Binary.sections[i];
        Elf64_Shdr* shdrPtr = elf64Binary.shdrs[i];
        uint32_t nameIdx = shdrPtr->sh_name;
        char* st = (char*)sStrTblPtr->data;

        sPtr->name = &st[nameIdx];
    }
}

// Parse all the section header names store in .shstrndx section. The
// first character in .shstrndx section is NULL, after that the NULL terminated
// strings can be found.
//
// The content of the section can be seen with the command.
//
//   $ readelf -x .shstrtab ./a.out
//   $ readelf -p .shstrtab ./a.out
//
// Note: The size of {@code elf64Binary.sectionNames} could be different from the
//       total number of sections. This is due that a string like
//       ".plt.got", in the string array, could also be used by the section
//       name ".got".
void Elf64Parser::ParseStringTableSection(Elf64Binary& elf64Binary, Elf64_Sc* sPtr) {
    char* st = (char*)sPtr->data;
    // First byte in the section is NULL, so it is ignored.
    uint64_t offRead = 1;
    elf64Binary.sectionNames.push_back(new std::string(""));

    if (sPtr->size <= 1) {
        return;
    }

    while (offRead < sPtr->size) {
        std::string* str = new std::string(&st[offRead]);
        elf64Binary.sectionNames.push_back(str);

        // Add the length of the string plus the null terminator.
        offRead += str->length() + 1;
    }
}

// Parse the Section Headers.
//
// Note: The command below can be used to print the section headers:
//
//   $ readelf --sections ./example_4k
//   $ readelf -S ./example_4k
void Elf64Parser::ParseSectionHeaders(std::ifstream& elfFile, Elf64Binary& elf64Binary) {
    uint64_t shOffset = elf64Binary.ehdr.e_shoff;
    uint16_t shNum = elf64Binary.ehdr.e_shnum;

    std::cout << "Parsing Section Headers" << std::endl;

    // Move the cursor position to the section headers offset.
    elfFile.seekg(shOffset);

    for (int i = 0; i < shNum; i++) {
        Elf64_Shdr* shdrPtr = new Elf64_Shdr;

        elfFile.read((char*)shdrPtr, sizeof(*shdrPtr));
        if (!elfFile.good()) {
            std::cerr << "Failed to read section header [" << i << "]" << std::endl;
            exit(-1);
        }

        elf64Binary.shdrs.push_back(shdrPtr);
    }
}

}  // namespace elf
}  // namespace lib
