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

#include <elf.h>
#include <gtest/gtest.h>
#include <mntent.h>

#include <regex>
#include <set>

#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android/api-level.h>
#include <elfpolicy/elf_policy.h>
#include <elfutils/iter.h>
#include <libdm/dm.h>

using ::android::elfutils::Elf64_File;

constexpr char kLowRamProp[] = "ro.config.low_ram";
constexpr char kVendorApiLevelProp[] = "ro.vendor.api_level";

// Unsupported devices must explicitly opt-out
constexpr uint64_t kRequiredMaxSupportedPageSize = ::android::elfpolicy::kMaxSupportedPageSize;

static inline std::string escapeForRegex(const std::string& str) {
    // Regex metacharacters to be escaped
    static const std::regex specialChars(R"([.^$|(){}\[\]+*?\\])");

    // Replace each special character with its escaped version
    return std::regex_replace(str, specialChars, R"(\$&)");
}

static inline bool startsWithPattern(const std::string& str, const std::string& pattern) {
    std::regex _pattern("^" + pattern + ".*");
    return std::regex_match(str, _pattern);
}

static std::set<std::string> getMounts() {
    std::unique_ptr<std::FILE, int (*)(std::FILE*)> fp(setmntent("/proc/mounts", "re"), endmntent);
    std::set<std::string> exclude({"/", "/config", "/data", "/data_mirror", "/dev", "/linkerconfig",
                                   "/mnt", "/proc", "/storage", "/sys"});
    std::set<std::string> mounts;

    if (fp == nullptr) {
        return mounts;
    }

    mntent* mentry;
    while ((mentry = getmntent(fp.get())) != nullptr) {
        std::string mountDir(mentry->mnt_dir);

        std::string dir = "/" + android::base::Split(mountDir, "/")[1];

        if (exclude.find(dir) != exclude.end()) {
            continue;
        }

        mounts.insert(dir);
    }

    return mounts;
}

using ::android::elfutils::ElfFile;

static bool isSystemPartition(const std::string& path) {
    static std::vector<std::string> system_partitions = {"/system", "/system_ext", "/product"};

    for (const auto& prefix : system_partitions) {
        if (android::base::StartsWith(path, prefix + "/")) {
            return true;
        }
    }

    return false;
}

static bool isVendorPartition(const std::string path) {
    return !isSystemPartition(path);
}

class ElfAlignmentTest : public ::testing::TestWithParam<std::string> {
  protected:
    static void loadAlignmentCb(ElfFile& elfFile) {
        using namespace android::elfutils;

        static std::array ignored_directories{
                // Ignore VNDK APEXes. They are prebuilts from old branches, and would
                // only be used on devices with old vendor images.
                escapeForRegex("/apex/com.android.vndk.v"),
                // Ignore Trusty VM images under */etc/vm/trusty_vm as they don't run
                // in userspace, so 16K is not required. See b/365240530 and b/406626518
                // for more context.
                ".*" + escapeForRegex("/etc/vm/trusty_vm"),
                // Ignore non-Android firmware images.
                escapeForRegex("/odm/firmware/"), escapeForRegex("/vendor/firmware/"),
                escapeForRegex("/vendor/firmware_mnt/image"),
                // Ignore TEE binaries ("glob: /apex/com.*.android.authfw.ta*")
                escapeForRegex("/apex/com.") + ".*" + escapeForRegex(".android.authfw.ta"),
                // Ignore wlan debug vendor prebuilts
                escapeForRegex("/vendor/bin/dhd"),
                escapeForRegex("/vendor/bin/wl")};

        // Don't check 32-bit ELFs, as 16k alignment is only required for 64-bit processes.
        if (elfFile.is32Bit()) {
            return;
        }

        std::string path = elfFile.getPath();
        for (const auto& pattern : ignored_directories) {
            if (startsWithPattern(path, pattern)) {
                return;
            }
        }

        // Ignore ART Odex files for now. They are not 16K aligned.
        // b/376814207
        if (path.ends_with(".odex")) {
            return;
        }

        std::string errorMsg;
        EXPECT_TRUE(android::elfpolicy::VerifyLoadSegmentsAlignment(
                elfFile, kRequiredMaxSupportedPageSize, errorMsg))
                << "File " << path << " failed 16k compatibility check: " << errorMsg;

        // Older toolchains have a bug in both GNU ld and LLVM lld which causes
        // the RELRO's end alignment to not respect the specified max-page-size.
        // See: https://developer.android.com/guide/practices/page-sizes#compile-r22-lower
        //
        // However since vendors are allowed to upgrade Android versions without
        // updating vendor partitions due to GRF; only enfore this on /vendor/
        // starting from chipset version 202604 -- where it is implicitly required
        // in order to implement [GMS-VSR-3.14.1-004] and [GMS-VSR-3.14.1-005]
        if (vendorApiLevel() < 202604 && isVendorPartition(path)) {
            return;
        }

        EXPECT_TRUE(android::elfpolicy::VerifyRelroSegments(elfFile, kRequiredMaxSupportedPageSize,
                                                            errorMsg))
                << "File " << path << " failed RELRO segment check: " << errorMsg;
    };

    static bool isLowRamDevice() { return android::base::GetBoolProperty(kLowRamProp, false); }

    static int vendorApiLevel() {
        // "ro.vendor.api_level" is added in Android T. Undefined indicates S or below
        return android::base::GetIntProperty(kVendorApiLevelProp, __ANDROID_API_S__);
    }

    void SetUp() override {
        if (vendorApiLevel() < 202404) {
            GTEST_SKIP() << "16kB support is only required on V and later releases.";
        } else if (isLowRamDevice()) {
            GTEST_SKIP() << "Low Ram devices only support 4kB page size";
        }
    }
};

using ::android::elfutils::ElfIterator;

// @VsrTest = 3.14.1
TEST_P(ElfAlignmentTest, VerifyLoadSegmentAlignment) {
    ElfIterator::forEachElfFromDir(GetParam(), &loadAlignmentCb);
}

INSTANTIATE_TEST_SUITE_P(ElfTestPartitionsAligned, ElfAlignmentTest,
                         ::testing::ValuesIn(getMounts()));

int main(int argc, char* argv[]) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
