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

#include "aac.h"

#include <android-base/file.h>
#include <gtest/gtest.h>

TEST(AppAlignmentCheckerTest, EmptyInput) {
    std::vector<PathInfo> paths;
    AppAlignmentChecker checker(paths);
    EXPECT_TRUE(checker.run());
}

TEST(AppAlignmentCheckerTest, NonExistentInput) {
    std::vector<PathInfo> paths = {{"/path/to/nowhere", "nowhere"}};
    AppAlignmentChecker checker(paths);
    EXPECT_TRUE(checker.run());
}

TEST(AppAlignmentCheckerTest, DummyNonElfNonApk) {
    TemporaryFile tf;
    std::vector<PathInfo> paths = {{tf.path, "dummy"}};
    AppAlignmentChecker checker(paths);
    EXPECT_TRUE(checker.run());
}

TEST(AppAlignmentCheckerTest, InvalidApkFails) {
    TemporaryDir td;
    std::filesystem::path apkPath = std::filesystem::path(td.path) / "invalid.apk";
    android::base::WriteStringToFile("not an apk", apkPath.string());

    std::vector<PathInfo> paths = {{apkPath, "invalid.apk"}};
    AppAlignmentChecker checker(paths);
    EXPECT_FALSE(checker.run());
}

TEST(AppAlignmentCheckerTest, ValidApkPasses) {
    TemporaryDir td;
    std::filesystem::path apkPath = std::filesystem::path(td.path) / "valid.apk";

    // An empty but structurally valid zip file.
    const char kEmptyZip[] = {'\x50', '\x4b', '\x05', '\x06', '\x00', '\x00', '\x00', '\x00',
                              '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
                              '\x00', '\x00', '\x00', '\x00', '\x00', '\x00'};

    android::base::WriteStringToFile(std::string(kEmptyZip, sizeof(kEmptyZip)), apkPath.string());

    std::vector<PathInfo> paths = {{apkPath, "valid.apk"}};
    AppAlignmentChecker checker(paths);
    EXPECT_TRUE(checker.run());
}

TEST(AppAlignmentCheckerTest, MultipleApksWithOneInvalidFails) {
    TemporaryDir td;
    std::filesystem::path validApkPath = std::filesystem::path(td.path) / "valid.apk";
    std::filesystem::path invalidApkPath = std::filesystem::path(td.path) / "invalid.apk";

    // An empty but structurally valid zip file.
    const char kEmptyZip[] = {'\x50', '\x4b', '\x05', '\x06', '\x00', '\x00', '\x00', '\x00',
                              '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
                              '\x00', '\x00', '\x00', '\x00', '\x00', '\x00'};

    android::base::WriteStringToFile(std::string(kEmptyZip, sizeof(kEmptyZip)),
                                     validApkPath.string());
    android::base::WriteStringToFile("not an apk", invalidApkPath.string());

    // Processing invalid then valid should result in overall failure,
    // ensuring a subsequent success doesn't overwrite a previous failure.
    std::vector<PathInfo> paths = {{invalidApkPath, "invalid.apk"}, {validApkPath, "valid.apk"}};
    AppAlignmentChecker checker(paths);
    EXPECT_FALSE(checker.run());
}
