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

#include <iostream>
#include <vector>

// Parses command-line arguments, validates paths.
// Returns true if the program should proceed, false otherwise.
bool ParseArguments(int argc, char* argv[], std::vector<PathInfo>& initialPaths) {
    if (argc < 2) return false;

    bool argsOk = true;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        // main will print help and exit
        if (arg == "-h" || arg == "--help") return false;

        std::filesystem::path path(arg);
        std::error_code ec;
        if (!std::filesystem::exists(path, ec)) {
            std::cout << "Error: Initial path does not exist: " << path << std::endl;
            argsOk = false;
        } else {
            initialPaths.push_back({path, path.filename().string()});
        }
    }

    return argsOk;
}

int main(int argc, char* argv[]) {
    std::vector<PathInfo> initialPaths;
    if (!ParseArguments(argc, argv, initialPaths) || initialPaths.empty()) {
        AppAlignmentChecker::printHelp(argv[0]);
        return EXIT_FAILURE;
    }

    AppAlignmentChecker checker(initialPaths);
    bool all_passed = checker.run();

    std::cout << std::endl;
    if (all_passed) {
        std::cout << "All checks passed." << std::endl;
        return EXIT_SUCCESS;
    } else {
        std::cout << "Some checks failed." << std::endl;
        return EXIT_FAILURE;
    }
}
