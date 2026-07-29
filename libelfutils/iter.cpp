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

#include <android-base/logging.h>
#include <archivestager/archive_stager.h>
#include <elfutils/elf-file.h>
#include <elfutils/iter.h>
#include <elfutils/parse.h>

#include <algorithm>
#include <cctype>
#include <filesystem>

namespace fs = std::filesystem;

namespace android {
namespace elfutils {

int ElfIterator::forEachElfFromDir(const std::string& dir, const ElfCallback& callback,
                                   bool unwrapZips) {
    int nrParsed = 0;

    for (const fs::directory_entry& dirEntry : fs::recursive_directory_iterator(dir)) {
        if (dirEntry.is_symlink() || !dirEntry.is_regular_file()) continue;

        const fs::path file = dirEntry.path();

        if (unwrapZips) {
            // Unwrap APKs and ZIPs.
            std::string fileExtension = file.extension().string();
            std::transform(fileExtension.begin(), fileExtension.end(), fileExtension.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            if (fileExtension == ".apk" || fileExtension == ".zip") {
                fs::path stagedEntriesRootDir = "";
                bool allPassed = stageArchiveContents(file, stagedEntriesRootDir);
                if (allPassed) {
                    nrParsed +=
                            forEachElfFromDir(stagedEntriesRootDir.string(), callback, unwrapZips);
                }
                if (!stagedEntriesRootDir.empty()) {
                    std::error_code ec;
                    fs::remove_all(stagedEntriesRootDir, ec);
                }
                continue;
            }
        }

        std::unique_ptr<ElfFile> elfFile = ElfFile::create(file.string());
        if (!elfFile) continue;

        nrParsed++;

        callback(*elfFile);
    }

    return nrParsed;
}

}  // namespace elfutils
}  // namespace android
