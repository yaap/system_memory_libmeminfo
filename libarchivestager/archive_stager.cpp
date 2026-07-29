/*
 * Copyright (C) 2026 The Android Open Source Project
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

#include <android-base/file.h>
#include <android-base/unique_fd.h>
#include <archivestager/archive_stager.h>
#include <fcntl.h>
#include <ziparchive/zip_archive.h>
#include <ziparchive/zip_error.h>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

using Path = std::filesystem::path;

#ifdef _WIN32
static char* mkdtemp(char* tmpl) {
    if (mktemp(tmpl) == NULL) {
        return NULL;
    }
    if (mkdir(tmpl) == -1) {
        return NULL;
    }
    return tmpl;
}
#endif

bool stageArchiveContents(const fs::path& archivePath, fs::path& stagedEntriesRootDir) {
    std::string tempDirTemplateStr =
            (fs::temp_directory_path() / "staged_archives_XXXXXX").string();
    std::vector<char> tempDirTemplate(tempDirTemplateStr.begin(), tempDirTemplateStr.end());
    tempDirTemplate.push_back('\0');

    char* tempDirCstr = mkdtemp(tempDirTemplate.data());
    if (tempDirCstr == nullptr) {
        std::cout << "Failed to create temporary directory for " << tempDirTemplate.data()
                  << std::endl;
        return false;
    }
    fs::path tempPath(tempDirCstr);

    ZipArchiveHandle handle;
    int32_t openResult = OpenArchive(archivePath.string().c_str(), &handle);
    if (openResult != 0) {
        if (openResult == kEmptyArchive) {
            std::cout << "Archive " << archivePath.string().c_str()
                      << " is empty. Skipping extraction." << std::endl;
            std::error_code ec;
            fs::remove_all(tempPath, ec);
            return true;
        }

        std::cout << "Failed to open archive " << archivePath.string().c_str() << ": "
                  << ErrorCodeString(openResult) << std::endl;
        CloseArchive(handle);
        std::error_code ec;
        fs::remove_all(tempPath, ec);
        return false;
    }

    void* cookie;
    if (StartIteration(handle, &cookie) != 0) {
        std::cout << "Failed to start iteration on archive " << archivePath.string().c_str()
                  << std::endl;
        CloseArchive(handle);
        std::error_code ec;
        fs::remove_all(tempPath, ec);
        return false;
    }

    ZipEntry64 entry;
    std::string name;
    bool allPassed = true;
    while (Next(cookie, &entry, &name) == 0) {
        fs::path outPath = tempPath / name;
        if (name.back() == '/') {
            fs::create_directories(outPath);
            continue;
        }

        fs::create_directories(outPath.parent_path());
        int open_flags = O_WRONLY | O_CREAT | O_TRUNC;
#ifdef _WIN32
        open_flags |= O_BINARY;
#endif
        android::base::unique_fd fd(open(outPath.string().c_str(), open_flags, entry.unix_mode));

        if (fd == -1) {
            std::cout << "Failed to create file: " << outPath << std::endl;
            allPassed = false;
            continue;
        }

        ExtractEntryToFile(handle, &entry, fd);
    }

    EndIteration(cookie);
    CloseArchive(handle);

    stagedEntriesRootDir = tempPath;

    return allPassed;
}
