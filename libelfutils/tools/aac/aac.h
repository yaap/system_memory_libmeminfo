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

#pragma once

#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <elfutils/elf-file.h>

using ::android::elfutils::Elf64_File;
using ::android::elfutils::ElfFile;

// Holds the real on-disk path and the path to be displayed in output.
struct PathInfo {
    std::filesystem::path realPath;
    std::string displayPath;
};

// Represents a discovered ELF file, holding its path info and parsed object.
struct ElfFileEntry {
    PathInfo paths;
    std::unique_ptr<ElfFile> elfFile;
};

class AppAlignmentChecker {
  public:
    explicit AppAlignmentChecker(const std::vector<PathInfo>& initialPaths);
    ~AppAlignmentChecker();

    bool run();
    static void printHelp(const char* arg0);

  private:
    void discoverFiles();
    void runZipalignChecks();
    void runElfChecks();
    void extractAndQueue(const PathInfo& archivePathPair);
    std::optional<std::string> getNdkVersion(const Elf64_File& elfFile);
    std::vector<std::string> getToolchainStrings(const Elf64_File& elfFile);

    std::vector<PathInfo> mZipFiles;
    std::vector<ElfFileEntry> mElfFiles;
    std::vector<std::filesystem::path> mTempDirs;
    std::vector<PathInfo> mScanQueue;
    bool mAllPassed = true;
};
