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

#include "aac.h"

#include <fcntl.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <system_error>
#include <utility>
#include <vector>

#include <ZipAlign.h>
#include <android-base/file.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <archivestager/archive_stager.h>
#include <elfpolicy/elf_policy.h>
#include <elfutils/parse.h>
#include <ziparchive/zip_archive.h>
#include <ziparchive/zip_error.h>

using ::android::elfpolicy::kMaxSupportedPageSize;
using ::android::elfutils::Elf32_File;
using ::android::elfutils::Elf_Sc;
using ::android::elfutils::ElfFile;
using ::android::elfutils::ElfParser;

namespace fs = std::filesystem;

AppAlignmentChecker::AppAlignmentChecker(const std::vector<PathInfo>& initialPaths)
    : mScanQueue(initialPaths) {}

AppAlignmentChecker::~AppAlignmentChecker() {
    for (const auto& tempDir : mTempDirs) {
        fs::remove_all(tempDir);
    }
}

bool AppAlignmentChecker::run() {
    discoverFiles();
    runZipalignChecks();
    runElfChecks();

    return mAllPassed;
}

void AppAlignmentChecker::discoverFiles() {
    std::cout << "--- Discovering and extracting files ---" << std::endl;
    while (!mScanQueue.empty()) {
        PathInfo currentItem = mScanQueue.back();
        mScanQueue.pop_back();
        const auto& currentPath = currentItem.realPath;
        const auto& displayBase = currentItem.displayPath;

        std::error_code ec;
        if (fs::is_directory(currentPath, ec)) {
            for (const auto& entry : fs::directory_iterator(currentPath, ec)) {
                fs::path newDisplayPath = fs::path(displayBase) / entry.path().filename();
                mScanQueue.push_back({entry.path(), newDisplayPath.string()});
            }
        } else if (fs::is_regular_file(currentPath, ec)) {
            if (auto elfFile = ElfFile::createFromIdent(currentPath.string()); elfFile) {
                mElfFiles.push_back({currentItem, std::move(elfFile)});
            } else {
                // Not an ELF file, check for other types like APK.
                std::string extension = currentPath.extension().string();
                if (extension == ".apk") {
                    mZipFiles.push_back(currentItem);
                    extractAndQueue(currentItem);
                }
            }
        }
    }
}

void AppAlignmentChecker::extractAndQueue(const PathInfo& archivePathPair) {
    const auto& displayBase = archivePathPair.displayPath;
    fs::path stagedEntriesRootDir = fs::path("");
    mAllPassed = stageArchiveContents(archivePathPair.realPath, stagedEntriesRootDir) && mAllPassed;
    if (!stagedEntriesRootDir.empty()) {
        mScanQueue.push_back({stagedEntriesRootDir, displayBase});
        mTempDirs.push_back(stagedEntriesRootDir);
    }
}

void AppAlignmentChecker::runZipalignChecks() {
    std::cout << "\n--- Running Zipalign Checks ---" << std::endl;
    for (const auto& paths : mZipFiles) {
        const int alignment = 4;
        const bool pageAlignSharedLibs = true;
        const int targetPageSize = kMaxSupportedPageSize;
        const bool verbose = false;

        if (android::verify(paths.realPath.string().c_str(), alignment, verbose,
                            pageAlignSharedLibs, targetPageSize) != 0) {
            std::cout << "[ FAIL ] " << paths.displayPath << ": Zip alignment verification failed."
                      << std::endl;
            mAllPassed = false;
        } else {
            std::cout << "[ PASS ] " << paths.displayPath << std::endl;
        }
    }
}

void AppAlignmentChecker::runElfChecks() {
    std::cout << "\n--- Running ELF Compatibility Checks ---" << std::endl;
    for (auto& entry : mElfFiles) {
        const std::string& displayPath = entry.paths.displayPath;
        std::unique_ptr<ElfFile>& elfFile = entry.elfFile;
        std::string errorMsg;

        // The 16KB and RELRO checks are only applicable to 64-bit ELF files.
        // Silently ignore 32-bit files as they are not subject to these requirements.
        if (elfFile->is32Bit()) {
            continue;
        }

        if (!elfFile->parseProgramHeaders()) {
            std::cout
                    << "[ WARN ] " << displayPath << std::endl
                    << "          Potentially obfuscated or corrupted ELF file detected. Skipping."
                    << std::endl;
            continue;
        }

        bool alignmentOk = android::elfpolicy::VerifyLoadSegmentsAlignment(
                *elfFile, kMaxSupportedPageSize, errorMsg);
        if (!alignmentOk) {
            std::cout << "[ FAIL ] " << displayPath << " (LOAD Segments)" << std::endl;
            std::cout << "         " << errorMsg << std::endl;
        } else {
            std::cout << "[ PASS ] " << displayPath << " (LOAD Segments)" << std::endl;
        }

        errorMsg.clear();

        if (!elfFile->parseSections()) {
            std::cout << "[ WARN ] " << displayPath << std::endl
                      << "          Potentially obfuscated or corrupted ELF file detected; some "
                         "checks may be incomplete."
                      << std::endl;
        }

        bool relroOk =
                android::elfpolicy::VerifyRelroSegments(*elfFile, kMaxSupportedPageSize, errorMsg);
        if (!relroOk) {
            std::cout << "[ FAIL ] " << displayPath << " (RELRO Segment)" << std::endl;
            std::cout << "         " << errorMsg << std::endl;
        } else {
            if (!errorMsg.empty()) {
                std::cout << "[ WARN ] " << displayPath << " (RELRO Segment)" << std::endl;
                std::cout << "         " << errorMsg << std::endl;
            } else {
                std::cout << "[ PASS ] " << displayPath << " (RELRO Segment)" << std::endl;
            }
        }

        if (!alignmentOk || !relroOk) {
            mAllPassed = false;
            // Try to print NDK/toolchain info for context on any failure.
            // These functions will fail gracefully if the required sections weren't parsed.
            auto* elf64File = static_cast<Elf64_File*>(elfFile.get());
            if (auto ndkVersion = getNdkVersion(*elf64File); ndkVersion) {
                std::cout << "           NDK Version: " << *ndkVersion << std::endl;
            }
            auto toolchains = getToolchainStrings(*elf64File);
            if (!toolchains.empty()) {
                std::cout << "           Toolchain: " << toolchains[0] << std::endl;
                for (size_t i = 1; i < toolchains.size(); ++i) {
                    std::cout << "           | " << toolchains[i] << std::endl;
                }
            }
        }
    }
}

std::optional<std::string> AppAlignmentChecker::getNdkVersion(const Elf64_File& elfFile) {
    const auto& sections = elfFile.getSections();
    const Elf_Sc* noteSection = nullptr;
    for (const auto& section : sections) {
        if (section.name != ".note.android.ident") continue;
        noteSection = &section;
        break;
    }

    if (!noteSection) return std::nullopt;

    const char* p = noteSection->data.data();
    const char* end = p + noteSection->size;

    while (p < end) {
        // Not enough space for a header?
        if (p + sizeof(Elf64_Nhdr) > end) break;

        const Elf64_Nhdr* nhdr = reinterpret_cast<const Elf64_Nhdr*>(p);
        p += sizeof(Elf64_Nhdr);

        const char* name = p;
        p += (nhdr->n_namesz + 3) & ~3;  // 4-byte alignment

        const char* desc = p;
        p += (nhdr->n_descsz + 3) & ~3;  // 4-byte alignment

        // Note entry goes past the end of the section ?
        if (p > end) break;

        // NT_VERSION?
        if (nhdr->n_type != 1) continue;

        // Name is Android?
        if (nhdr->n_namesz != sizeof("Android")) continue;
        if (strcmp(name, "Android") != 0) continue;

        // Large enough?
        // The format is: API level (4 bytes), NDK version string (64 bytes), build ID (64 bytes)
        if (nhdr->n_descsz < 132) continue;

        // Parse the NDK version
        std::string ndkVersion(desc + 4, 64);

        // Trim null characters
        size_t firstNull = ndkVersion.find('\0');

        if (firstNull != std::string::npos) ndkVersion.resize(firstNull);

        return ndkVersion;
    }

    return std::nullopt;
}

// Toolchain strings are usually contained in the .comment section.
std::vector<std::string> AppAlignmentChecker::getToolchainStrings(const Elf64_File& elfFile) {
    std::vector<std::string> toolchains;
    const Elf_Sc* commentSection = elfFile.findSectionByName(".comment");

    if (!commentSection || commentSection->data.empty()) return toolchains;

    const char* start = commentSection->data.data();
    const char* end = start + commentSection->size;
    const char* current = start;

    while (current < end) {
        const char* strEnd = (const char*)memchr(current, '\0', end - current);
        if (strEnd == nullptr) break;

        bool isPrintable = true;
        for (const char* c = current; c < strEnd; ++c) {
            if (!isprint(*c)) {
                isPrintable = false;
                break;
            }
        }

        if (isPrintable) {
            std::string toolchainStr(current, strEnd - current);
            if (!toolchainStr.empty()) toolchains.push_back(toolchainStr);
        }

        current = strEnd + 1;
    }

    return toolchains;
}

void AppAlignmentChecker::printHelp(const char* arg0) {
    std::cout
            << "aac (App Alignment Checker)\n\n"
            << "Usage: " << arg0 << " <file_or_directory>...\n\n"
            << "A host tool to verify Android application packages (.apk) and ELF binaries (.so)\n"
            << "for modern compatibility requirements.\n\n"
            << "The tool performs the following checks:\n"
            << "  - Zipalign verification for APKs.\n"
            << "  - 16KB page alignment for ELF LOAD segments.\n"
            << "  - RELRO segment validity for ELF files.\n\n"
            << "It recursively scans directories and extracts APKs for deep analysis.\n\n"
            << "Options:\n"
            << "  -h, --help    Display this help message and exit.\n"
            << std::endl;
}
