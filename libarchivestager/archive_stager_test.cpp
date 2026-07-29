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
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <archivestager/archive_stager.h>
#include <gtest/gtest.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <vector>

namespace fs = std::filesystem;

TEST(ZiparchiveStagerTest, StageValidArchive) {
    auto exec_dir = android::base::GetExecutableDirectory();
    fs::path mZipFile = fs::path(exec_dir) / "testdata" / "test.apk";
    ASSERT_TRUE(fs::exists(mZipFile)) << "Zip file not found: " << mZipFile;

    fs::path stagedEntriesRootDir;

    bool allPassed = stageArchiveContents(mZipFile, stagedEntriesRootDir);

    EXPECT_TRUE(allPassed);
    EXPECT_FALSE(stagedEntriesRootDir.empty());
    EXPECT_TRUE(std::filesystem::is_directory(stagedEntriesRootDir));
    EXPECT_TRUE(android::base::StartsWith(stagedEntriesRootDir.filename().string(),
                                          "staged_archives_"));

    fs::path extracted_file = stagedEntriesRootDir / "test.txt";
    EXPECT_TRUE(std::filesystem::exists(extracted_file));

    std::string content;
    EXPECT_TRUE(android::base::ReadFileToString(extracted_file.string(), &content));
    EXPECT_EQ(content, "hello");

    std::filesystem::remove_all(stagedEntriesRootDir);
}

TEST(ZiparchiveStagerTest, StageInvalidArchive) {
    auto exec_dir = android::base::GetExecutableDirectory();
    fs::path mInvalidZipFile = fs::path(exec_dir) / "testdata" / "invalid.apk";
    ASSERT_TRUE(fs::exists(mInvalidZipFile)) << "Invalid zip file not found: " << mInvalidZipFile;

    fs::path stagedEntriesRootDir;

    bool allPassed = stageArchiveContents(mInvalidZipFile, stagedEntriesRootDir);

    EXPECT_FALSE(allPassed);
    EXPECT_TRUE(stagedEntriesRootDir.empty());
}
