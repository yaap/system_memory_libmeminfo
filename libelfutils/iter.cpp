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
 * limitations under the License. */

#include <elfutils/elf-file.h>
#include <elfutils/iter.h>
#include <elfutils/parse.h>

#include <filesystem>

namespace android {
namespace elfutils {

int ElfIterator::forEachElfFromDir(const std::string& dir, const ElfCallback& callback) {
    int nrParsed = 0;

    for (const std::filesystem::directory_entry& dirEntry :
         std::filesystem::recursive_directory_iterator(dir)) {
        if (dirEntry.is_symlink() || !dirEntry.is_regular_file()) continue;

        std::string file = dirEntry.path();

        std::unique_ptr<ElfFile> elfFile = ElfFile::create(file);
        if (!elfFile) continue;

        nrParsed++;

        callback(*elfFile);
    }

    return nrParsed;
}

}  // namespace elfutils
}  // namespace android
