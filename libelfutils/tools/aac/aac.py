#!/usr/bin/env python3
#
# Copyright (C) 2025 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import argparse
import platform
import subprocess
import sys
import threading
import time
from pathlib import Path

def get_android_build_top():
    """Walks up the directory tree to find the Android root."""
    current_dir = Path(__file__).parent.resolve()
    while current_dir != current_dir.parent:
        if (current_dir / "build/soong/soong_ui.bash").is_file():
            return current_dir
        current_dir = current_dir.parent
    return None

def get_host_os_and_arch():
    """Determines the host OS and architecture for locating build outputs."""
    os_name = sys.platform
    arch = platform.machine()

    if os_name.startswith('linux'):
        if arch == 'x86_64':
            return 'linux', 'linux-x86'
        elif arch == 'aarch64':
            return 'linux', 'linux-arm64'
    elif os_name == 'darwin':
        if arch == 'x86_64':
            return 'darwin', 'darwin-x86'
        elif arch == 'arm64':
            return 'darwin', 'darwin-arm64'
    elif os_name == 'win32':
        if arch == 'AMD64':
            return 'windows', 'windows-x86'
        elif arch == 'ARM64':
            return 'windows', 'windows-arm64'

    return None, None

def spinner_animation(stop_event):
    """Displays a spinner animation in the console."""
    spinner_chars = "|/-\\"
    while not stop_event.is_set():
        for char in spinner_chars:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(0.1)
            sys.stdout.write('\b')

def main():
    """Builds and executes the aac tool."""
    parser = argparse.ArgumentParser(
        description="Build and run the aac (App Alignment Checker) tool.",
        epilog="All other arguments will be passed to the aac tool."
    )
    parser.add_argument('--verbose', action='store_true',
                        help='Stream full build output in real-time.')
    parser.add_argument('aac_args', nargs=argparse.REMAINDER,
                        help='Arguments to pass to the aac tool')
    args = parser.parse_args()

    android_top = get_android_build_top()
    if not android_top:
        print("Error: Could not find the Android build root.", file=sys.stderr)
        return 1

    host_os, host_path = get_host_os_and_arch()
    if not host_os:
        print(f"Error: Unsupported host OS/arch: "
              f"{sys.platform}/{platform.machine()}", file=sys.stderr)
        return 1

    aac_binary_name = "aac.exe" if host_os == "windows" else "aac"
    aac_path = android_top / "out/host" / host_path / "bin" / aac_binary_name

    if not aac_path.is_file():
        build_command = [
            "build/soong/soong_ui.bash",
            "--make-mode",
            "TARGET_PRODUCT=aosp_cf_x86_64_phone",
            "TARGET_RELEASE=trunk",
            "TARGET_BUILD_VARIANT=userdebug",
            f"HOST_OS={host_os}",
            "aac",
        ]

        if args.verbose:
            print("--- Building aac tool (verbose) ---")
            result = subprocess.run(build_command, cwd=android_top, check=False)
        else:
            print("--- Building aac tool --- ", end="")
            stop_spinner = threading.Event()
            spinner_thread = threading.Thread(target=spinner_animation,
                                              args=(stop_spinner,))
            spinner_thread.start()
            try:
                result = subprocess.run(build_command, cwd=android_top,
                                        check=False, capture_output=True,
                                        text=True)
            finally:
                stop_spinner.set()
                spinner_thread.join()
                sys.stdout.write("\b \b")

        if result.returncode != 0:
            print("\nError: aac build failed.", file=sys.stderr)
            if not args.verbose:
                print(result.stderr, file=sys.stderr)
            return 1

        if not args.verbose:
            print("Done.")
    else:
        print(f"--- Found pre-built aac tool at {aac_path} ---")


    if not aac_path.is_file():
        print(f"Error: Could not find aac binary at {aac_path}",
              file=sys.stderr)
        return 1

    # Execute the aac tool with the provided arguments.
    print("\n--- Running aac tool ---")
    exec_command = [str(aac_path)] + args.aac_args
    result = subprocess.run(exec_command, check=False)

    return result.returncode

if __name__ == "__main__":
    sys.exit(main())
