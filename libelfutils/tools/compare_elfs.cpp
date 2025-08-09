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

#include <elfutils/comparator.h>
#include <elfutils/elf-file.h>
#include <elfutils/parse.h>

#include <iostream>
#include <set>
#include <string>
#include <vector>

#include <elf.h>
#include <libgen.h>
#include <stdlib.h>

void usage(char* progname) {
    std::cout << "Usage: " << progname << " [ELF1] [ELF2]\n"
              << R"(
Options:
ELF1    ELF1 to be compare with ELF2
ELF2    ELF2 to be compare with ELF1
)" << "\n";
}

using ::android::elfutils::ElfComparator;
using ::android::elfutils::ElfFile;

// Compare ELFs (shared libraries, executables)
int main(int argc, char* argv[]) {
    if (argc < 3) {
        usage(basename(argv[0]));
        return EXIT_FAILURE;
    }

    std::string elfName1(argv[1]);
    std::string elfName2(argv[2]);

    std::unique_ptr<ElfFile> elfFile1 = ElfFile::create(elfName1);
    if (!elfFile1) {
        std::cerr << "Failed to create or parse file " << elfName1 << "\n";
        return EXIT_FAILURE;
    }

    std::unique_ptr<ElfFile> elfFile2 = ElfFile::create(elfName2);
    if (!elfFile2) {
        std::cerr << "Failed to create or parse file " << elfName2 << "\n";
        return EXIT_FAILURE;
    }

    auto comparator = ElfComparator::create(*elfFile1, *elfFile2);
    if (!comparator) {
        std::cerr << "Failed to create comparator. Are the ELF files of the same architecture?\n";
        return EXIT_FAILURE;
    }

    if (comparator->compareHeaders()) {
        std::cout << "Executable Headers are equal" << "\n";
    } else {
        std::cout << "Executable Headers are NOT equal" << "\n";
    }

    if (comparator->compareProgramHeaders()) {
        std::cout << "Program Headers are equal" << "\n";
    } else {
        std::cout << "Program Headers are NOT equal" << "\n";
    }

    if (comparator->compareSectionHeaders()) {
        std::cout << "Section Headers are equal" << "\n";
    } else {
        std::cout << "Section Headers are NOT equal" << "\n";
    }

    if (comparator->compareSections()) {
        std::cout << "Sections are equal" << "\n";
    } else {
        std::cout << "Sections are NOT equal" << "\n";
    }

    return 0;
}
