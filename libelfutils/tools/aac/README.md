# aac (App Alignment Checker)

`aac` is a host command-line tool designed to verify that Android application packages
(`.apk`) and the ELF binaries (`.so`) within them meet modern Android compatibility
requirements.

## Checks Performed

The tool performs a multi-pass scan on the provided files and directories:

1.  **APK Discovery & Extraction**: Recursively finds all `.apk` files and extracts them to a
    temporary directory for deep analysis.
2.  **Zipalign Verification**: For each `.apk`, it verifies that all uncompressed entries are
    correctly aligned, which is a requirement for efficient memory mapping.
3.  **ELF Compatibility Checks**: For each ELF file (either standalone or extracted from an
    APK), it performs two critical validations:
    *   **LOAD Segment Alignment**: Verifies that all `PT_LOAD` segments are aligned to at
        least a 16KB boundary, a requirement for devices with 16KB page sizes.
    *   **RELRO Segment Validity**: Verifies that the `PT_GNU_RELRO` segment is correctly
        aligned and contained within a corresponding `PT_LOAD` segment. It also provides
        NDK version information on failure to help with debugging.

## Usage

The recommended way to run the tool is via the `aac.py` wrapper script.
This script automatically handles building the tool if it's not already
built and then executes it, passing along any arguments.

The script will recursively scan any directories provided.

```bash
# From the aac tool directory:
./aac.py /path/to/your/app.apk
./aac.py /path/to/directory/of/apks
./aac.py /path/to/some/native_library.so
```

### Example Output
```sh
--- Found pre-built aac tool at /path/to/android/out/host/linux-x86/bin/aac ---

--- Running aac tool ---
--- Discovering and extracting files ---

--- Running Zipalign Checks ---
[ PASS ] my_app.apk

--- Running ELF Compatibility Checks ---
[ PASS ] my_app.apk/lib/arm64-v8a/libmain.so (LOAD Segments)
[ PASS ] my_app.apk/lib/arm64-v8a/libmain.so (RELRO Segment)
[ FAIL ] my_app.apk/lib/arm64-v8a/libvendor.so (LOAD Segments): Not at least 16KiB aligned.
Minimum alignment: 4096
[ FAIL ] my_app.apk/lib/arm64-v8a/libvendor.so (RELRO Segment): Unaligned RELRO end 0xa1000
must match LOAD end 0xa1568 (NDK Version: r16b)
[ WARN ] my_app.apk/lib/arm64-v8a/libobfuscated.so (RELRO Segment): RELRO not contained
within any LOAD segment. Skipping check (likely obfuscated).

Some checks failed.
```

## Debugging

A `--verbose` option provided for debugging build failures.

# From the aac tool directory:
```sh
./aac.py --verbose /path/to/your/app.apk
```
