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

#include <libelf64/elf64.h>
#include <libelf64/elf64_writer.h>
#include <libelf64/parse.h>

#include <iostream>
#include <set>
#include <string>
#include <vector>

#include <elf.h>
#include <stdlib.h>

// Remove the sharedLibs from the .dynamic section.
// In order to remove the sharedLibs from the .dynamic
// section, it sets the Elf64_Dyn.d_tag to DT_DEBUG.
void remove_needed_shared_libs(android::elf64::Elf64Binary& elf64Binary,
                               std::set<std::string>& sharedLibs) {
    std::vector<Elf64_Dyn> dynEntries;

    elf64Binary.AppendDynamicEntries(&dynEntries);

    for (int i = 0; i < dynEntries.size(); i++) {
        if (dynEntries[i].d_tag == DT_NEEDED) {
            std::string libName = elf64Binary.GetStrFromDynStrTable(dynEntries[i].d_un.d_val);

            if (sharedLibs.count(libName)) {
                dynEntries[i].d_tag = DT_DEBUG;
            }
        }
    }

    elf64Binary.SetDynamicEntries(&dynEntries);
}

void set_exec_segments_as_rwx(android::elf64::Elf64Binary& elf64Binary) {
    for (int i = 0; i < elf64Binary.phdrs.size(); i++) {
        if (elf64Binary.phdrs[i].p_flags & PF_X) {
            elf64Binary.phdrs[i].p_flags |= PF_W;
        }
    }
}

// Generates a shared library with the executable segments as read/write/exec.
void gen_lib_with_rwx_segment(const android::elf64::Elf64Binary& elf64Binary,
                              std::string newSharedLibName) {
    android::elf64::Elf64Binary copyElf64Binary = elf64Binary;
    set_exec_segments_as_rwx(copyElf64Binary);
    android::elf64::Elf64Writer::WriteElf64File(copyElf64Binary, newSharedLibName);
}

void usage() {
    const std::string progname = getprogname();

    std::cout << "Usage: " << progname << " [shared_lib] [out_dir]...\n"
              << R"(
Options:
shared_lib       shared library that will be used as reference.
out_dir          the invalid shared libraries that are
                 generated will be placed in this directory.)"
              << std::endl;
}

// Generate shared libraries with invalid:
//
//   - executable header
//   - segment headers
//   - section headers
int main(int argc, char* argv[]) {
    if (argc < 3) {
        usage();
        return EXIT_FAILURE;
    }

    std::string baseSharedLibName(argv[1]);
    std::string outputDir(argv[2]);

    android::elf64::Elf64Binary elf64Binary;
    if (android::elf64::Elf64Parser::ParseElfFile(baseSharedLibName, elf64Binary)) {
        std::set<std::string> libsToRemove = {"libc++_shared.so"};
        remove_needed_shared_libs(elf64Binary, libsToRemove);

        gen_lib_with_rwx_segment(elf64Binary, outputDir + "/libtest_invalid-rw_load_segment.so");
    }

    return 0;
}
