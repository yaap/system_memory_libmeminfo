/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <functional>
#include <iterator>
#if defined(__ANDROID__) && !defined(__ANDROID_APEX__) && !defined(__ANDROID_VNDK__)
#include "bpf/BpfMap.h"
#endif
#include <regex>
#include <sstream>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <dmabufinfo/dmabuf_per_buffer_stats.h>

#include "meminfo_private.h"
#include "libdmabufinfo/dmabuf_sysfs_stats.h"

namespace android {
namespace meminfo {

using DmabufTotal = dmabufinfo::DmabufTotal;
using ExporterName = dmabufinfo::DmabufPerBufferStats::ExporterName;

bool SysMemInfo::ReadMemInfo(const char* path) {
    return ReadMemInfo(path, SysMemInfo::kDefaultSysMemInfoTags.size(),
                       &*SysMemInfo::kDefaultSysMemInfoTags.begin(),
                       [&](std::string_view tag, uint64_t val) {
                           // Safe to store the string_view in the map
                           // because the tags from
                           // kDefaultSysMemInfoTags are all
                           // statically-allocated.
                           mem_in_kb_[tag] = val;
                       });
}

bool SysMemInfo::ReadMemInfo(std::vector<uint64_t>* out, const char* path) {
    out->clear();
    out->resize(SysMemInfo::kDefaultSysMemInfoTags.size());
    return ReadMemInfo(SysMemInfo::kDefaultSysMemInfoTags.size(),
                       &*SysMemInfo::kDefaultSysMemInfoTags.begin(), out->data(), path);
}

bool SysMemInfo::ReadMemInfo(size_t ntags, const std::string_view* tags, uint64_t* out,
                             const char* path) {
    return ReadMemInfo(path, ntags, tags, [&]([[maybe_unused]] std::string_view tag, uint64_t val) {
        auto it = std::find(tags, tags + ntags, tag);
        if (it == tags + ntags) {
            LOG(ERROR) << "Tried to store invalid tag: " << tag;
            return;
        }
        auto index = std::distance(tags, it);
        // store the values in the same order as the tags
        out[index] = val;
    });
}

uint64_t SysMemInfo::ReadVmallocInfo() {
    return ::android::meminfo::ReadVmallocInfo();
}

bool SysMemInfo::ReadMemInfo(const char* path, size_t ntags, const std::string_view* tags,
                             std::function<void(std::string_view, uint64_t)> store_val) {
    char buffer[4096];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        PLOG(ERROR) << "Failed to open file :" << path;
        return false;
    }

    const int len = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (len < 0) {
        return false;
    }

    buffer[len] = '\0';
    char* p = buffer;
    uint32_t found = 0;
    uint32_t lineno = 0;
    bool zram_tag_found = false;
    while (*p && found < ntags) {
        for (size_t tagno = 0; tagno < ntags; ++tagno) {
            const std::string_view& tag = tags[tagno];
            // Special case for "Zram:" tag that android_os_Debug and friends look
            // up along with the rest of the numbers from /proc/meminfo
            if (!zram_tag_found && tag == "Zram:") {
                store_val(tag, mem_zram_kb());
                zram_tag_found = true;
                found++;
                continue;
            }

            if (strncmp(p, tag.data(), tag.size()) == 0) {
                p += tag.size();
                while (*p == ' ') p++;
                char* endptr = nullptr;
                uint64_t val = strtoull(p, &endptr, 10);
                if (p == endptr) {
                    PLOG(ERROR) << "Failed to parse line:" << lineno + 1 << " in file: " << path;
                    return false;
                }
                store_val(tag, val);
                p = endptr;
                found++;
                break;
            }
        }

        while (*p && *p != '\n') {
            p++;
        }
        if (*p) p++;
        lineno++;
    }

    return true;
}

uint64_t SysMemInfo::mem_zram_kb(const char* zram_dev_cstr) const {
    uint64_t mem_zram_total = 0;
    if (zram_dev_cstr) {
        if (!MemZramDevice(zram_dev_cstr, &mem_zram_total)) {
            return 0;
        }
        return mem_zram_total / 1024;
    }

    constexpr uint32_t kMaxZramDevices = 256;
    for (uint32_t i = 0; i < kMaxZramDevices; i++) {
        std::string zram_dev_abspath = ::android::base::StringPrintf("/sys/block/zram%u/", i);
        if (access(zram_dev_abspath.c_str(), F_OK)) {
            // We assume zram devices appear in range 0-255 and appear always in sequence
            // under /sys/block. So, stop looking for them once we find one is missing.
            break;
        }

        uint64_t mem_zram_dev;
        if (!MemZramDevice(zram_dev_abspath.c_str(), &mem_zram_dev)) {
            return 0;
        }

        mem_zram_total += mem_zram_dev;
    }

    return mem_zram_total / 1024;
}

bool SysMemInfo::MemZramDevice(const char* zram_dev, uint64_t* mem_zram_dev) const {
    std::string mmstat = ::android::base::StringPrintf("%s/%s", zram_dev, "mm_stat");
    auto mmstat_fp = std::unique_ptr<FILE, decltype(&fclose)>{fopen(mmstat.c_str(), "re"), fclose};
    if (mmstat_fp != nullptr) {
        // only if we do have mmstat, use it. Otherwise, fall through to trying out the old
        // 'mem_used_total'
        if (fscanf(mmstat_fp.get(), "%*" SCNu64 " %*" SCNu64 " %" SCNu64, mem_zram_dev) != 1) {
            PLOG(ERROR) << "Malformed mm_stat file in: " << zram_dev;
            return false;
        }
        return true;
    }

    std::string content;
    if (::android::base::ReadFileToString(
                ::android::base::StringPrintf("%s/mem_used_total", zram_dev), &content)) {
        *mem_zram_dev = strtoull(content.c_str(), NULL, 10);
        if (*mem_zram_dev == ULLONG_MAX) {
            PLOG(ERROR) << "Malformed mem_used_total file for zram dev: " << zram_dev
                        << " content: " << content;
            return false;
        }

        return true;
    }

    LOG(ERROR) << "Can't find memory status under: " << zram_dev;
    return false;
}

uint64_t SysMemInfo::mem_compacted_kb(const char* zram_dev_cstr) {
    uint64_t mem_compacted_total = 0;
    if (zram_dev_cstr) {
        // Fast-path, single device
        if (!GetTotalMemCompacted(zram_dev_cstr, &mem_compacted_total)) {
            return 0;
        }
        return mem_compacted_total / 1024;
    }

    // Slow path - multiple devices
    constexpr uint32_t kMaxZramDevices = 256;
    for (uint32_t i = 0; i < kMaxZramDevices; i++) {
        std::string zram_dev_abspath = ::android::base::StringPrintf("/sys/block/zram%u/", i);
        if (access(zram_dev_abspath.c_str(), F_OK)) {
            // We assume zram devices appear in range 0-255 and appear always in sequence
            // under /sys/block. So, stop looking for them once we find one is missing.
            break;
        }

        uint64_t mem_compacted;
        if (!GetTotalMemCompacted(zram_dev_abspath.c_str(), &mem_compacted)) {
            return 0;
        }

        mem_compacted_total += mem_compacted;
    }

    return mem_compacted_total / 1024; // transform to KBs
}

// Returns the total memory compacted in bytes which corresponds to the following formula
// compacted memory = uncompressed memory size - compressed memory size
bool SysMemInfo::GetTotalMemCompacted(const char* zram_dev, uint64_t* out_mem_compacted) {
    std::string mmstat = ::android::base::StringPrintf("%s/%s", zram_dev, "mm_stat");
    auto mmstat_fp = std::unique_ptr<FILE, decltype(&fclose)>{fopen(mmstat.c_str(), "re"), fclose};
    if (mmstat_fp != nullptr) {
        uint64_t uncompressed_size_bytes;
        uint64_t compressed_size_bytes;

        if (fscanf(mmstat_fp.get(), "%" SCNu64 "%" SCNu64, &uncompressed_size_bytes,
                   &compressed_size_bytes) != 2) {
            PLOG(ERROR) << "Malformed mm_stat file in: " << zram_dev;
            *out_mem_compacted = 0;
            return false;
        }

        *out_mem_compacted = uncompressed_size_bytes - compressed_size_bytes;
        return true;
    }

    *out_mem_compacted = 0;
    return false;
}

// Public methods
uint64_t ReadVmallocInfo(const char* path) {
    uint64_t vmalloc_total = 0;
    auto fp = std::unique_ptr<FILE, decltype(&fclose)>{fopen(path, "re"), fclose};
    if (fp == nullptr) {
        return vmalloc_total;
    }

    char* line = nullptr;
    size_t line_alloc = 0;
    while (getline(&line, &line_alloc, fp.get()) > 0) {
        // We are looking for lines like
        //
        // 0x0000000000000000-0x0000000000000000   12288 drm_property_create_blob+0x44/0xec pages=2 vmalloc
        // 0x0000000000000000-0x0000000000000000    8192 wlan_logging_sock_init_svc+0xf8/0x4f0 [wlan] pages=1 vmalloc
        //
        // Notice that if the caller is coming from a module, the kernel prints and extra
        // "[module_name]" after the address and the symbol of the call site. This means we can't
        // use the old sscanf() method of getting the # of pages.
        char* p_start = strstr(line, "pages=");
        if (p_start == nullptr) {
            // we didn't find anything
            continue;
        }

        uint64_t nr_pages;
        if (sscanf(p_start, "pages=%" SCNu64 "", &nr_pages) == 1) {
            vmalloc_total += (nr_pages * getpagesize());
        }
    }

    free(line);

    return vmalloc_total;
}

static bool ReadSysfsFile(const std::string& path, uint64_t* value) {
    std::string content;
    if (!::android::base::ReadFileToString(path, &content)) {
        LOG(ERROR) << "Can't open file: " << path;
        return false;
    }

    *value = strtoull(content.c_str(), NULL, 10);
    if (*value == ULLONG_MAX) {
        PLOG(ERROR) << "Invalid file format: " << path;
        return false;
    }

    return true;
}

[[deprecated("Retained for binary compatibility for GRF")]]
bool ReadIonHeapsSizeKb(uint64_t*, const std::string&) {
    return false;
}

[[deprecated("Retained for binary compatibility for GRF")]]
bool ReadIonPoolsSizeKb(uint64_t*, const std::string&) {
    return false;
}

bool ReadDmabufHeapPoolsSizeKb(uint64_t* size, const std::string& dma_heap_pool_size_path) {
    static bool support_dmabuf_heap_pool_size = [dma_heap_pool_size_path]() -> bool {
        bool ret = (access(dma_heap_pool_size_path.c_str(), R_OK) == 0);
        if (!ret) LOG(ERROR) << "Unable to read DMA-BUF heap total pool size";
        return ret;
    }();

    if (!support_dmabuf_heap_pool_size) return false;

    return ReadSysfsFile(dma_heap_pool_size_path, size);
}

static std::unordered_set<ExporterName> GetDmabufHeapNames(const std::string& dma_heap_root_path) {
    std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(dma_heap_root_path.c_str()), closedir);

    if (!dir) {
        return {};
    }

    std::unordered_set<ExporterName> heap_list;
    struct dirent* dent;
    while ((dent = readdir(dir.get()))) {
        if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, "..")) continue;

        heap_list.insert(dent->d_name);
    }

    return heap_list;
}

static uint64_t AccumulateHeapTotals(const std::unordered_set<ExporterName>& heap_list,
        const std::unordered_map<ExporterName, DmabufTotal>& exporter_info) {
    uint64_t size = 0;
    for (const auto& heap : heap_list) {
        auto iter = exporter_info.find(heap);
        if (iter != exporter_info.end()) size += iter->second.size;
    }

    size /= 1024; // KiB

    return size;
}

bool ReadDmabufHeapTotalExportedKb(uint64_t* size) {
    constexpr const char DMABUF_HEAP_ROOT_PATH[] = "/dev/dma_heap";
    static bool support_dmabuf_heaps = [DMABUF_HEAP_ROOT_PATH]() -> bool {
        int access_ret = access(DMABUF_HEAP_ROOT_PATH, R_OK);
        bool ret = (access_ret == 0);
        if (!ret) {
            LOG(ERROR) << "DMA-BUF heaps not supported. access() returned " << access_ret
                       << ", errno: " << strerror(errno);
        }
        return ret;
    }();

    if (!support_dmabuf_heaps) return false;

    std::unordered_set<ExporterName> heap_list = GetDmabufHeapNames(DMABUF_HEAP_ROOT_PATH);
    if (heap_list.empty()) return false;

    android::dmabufinfo::DmabufPerBufferStats stats;
    if (!android::dmabufinfo::GetDmabufPerBufferStats(stats)) return false;

    *size = AccumulateHeapTotals(heap_list, stats.exporter_info());

    return true;
}

[[deprecated("Retained for binary compatibility for GRF and for libmeminfo_test")]]
bool ReadDmabufHeapTotalExportedKb(
        uint64_t* size, const std::string& dma_heap_root_path,
        const std::string& dmabuf_sysfs_stats_path) {

    std::unordered_set<ExporterName> heap_list = GetDmabufHeapNames(dma_heap_root_path);
    if (heap_list.empty()) return false;

    android::dmabufinfo::DmabufPerBufferStats stats;
    if (!android::dmabufinfo::GetDmabufSysfsStats(stats, dmabuf_sysfs_stats_path)) return false;

    *size = AccumulateHeapTotals(heap_list, stats.exporter_info());

    return true;
}

bool ReadPerProcessGpuMem([[maybe_unused]] std::unordered_map<uint32_t, uint64_t>* out) {
#if defined(__ANDROID__) && !defined(__ANDROID_APEX__) && !defined(__ANDROID_VNDK__)
    static constexpr const char kBpfGpuMemTotalMap[] = "/sys/fs/bpf/map_gpuMem_gpu_mem_total_map";

    if (access(kBpfGpuMemTotalMap, F_OK)) {
        LOG(ERROR) << "ReadPerProcessGpuMem: GpuMem tracing is disabled in kernel. Skipping!";
        return false;
    }

    // Use the read-only wrapper BpfMapRO to properly retrieve the read-only map.
    auto map = bpf::BpfMapRO<uint64_t, uint64_t>(kBpfGpuMemTotalMap);
    if (!map.isValid()) {
        LOG(ERROR) << "Can't open file: " << kBpfGpuMemTotalMap;
        return false;
    }

    if (!out) {
        LOG(ERROR) << "ReadPerProcessGpuMem: out param is null";
        return false;
    }
    out->clear();

    auto map_key = map.getFirstKey();
    if (!map_key.ok()) {
        return true;
    }

    do {
        uint64_t key = map_key.value();
        uint32_t pid = key;  // BPF Key [32-bits GPU ID | 32-bits PID]

        auto gpu_mem = map.readValue(key);
        if (!gpu_mem.ok()) {
            LOG(ERROR) << "Invalid file format: " << kBpfGpuMemTotalMap;
            return false;
        }

        const auto& iter = out->find(pid);
        if (iter == out->end()) {
            out->insert({pid, gpu_mem.value() / 1024});
        } else {
            iter->second += gpu_mem.value() / 1024;
        }

        map_key = map.getNextKey(key);
    } while (map_key.ok());

    return true;
#else
    return false;
#endif
}

bool ReadProcessGpuUsageKb([[maybe_unused]] uint32_t pid, [[maybe_unused]] uint32_t gpu_id,
                           uint64_t* size) {
#if defined(__ANDROID__) && !defined(__ANDROID_APEX__) && !defined(__ANDROID_VNDK__)
    static constexpr const char kBpfGpuMemTotalMap[] = "/sys/fs/bpf/map_gpuMem_gpu_mem_total_map";

    if (access(kBpfGpuMemTotalMap, F_OK)) {
        LOG(ERROR) << "ReadProcessGpuUsageKb: GpuMem tracing is disabled in kernel. Skipping!";
        return false;
    }

    uint64_t gpu_mem;

    // BPF Key [32-bits GPU ID | 32-bits PID]
    uint64_t kBpfKeyGpuUsage = ((uint64_t)gpu_id << 32) | pid;

    // Use the read-only wrapper BpfMapRO to properly retrieve the read-only map.
    auto map = bpf::BpfMapRO<uint64_t, uint64_t>(kBpfGpuMemTotalMap);
    if (!map.isValid()) {
        LOG(ERROR) << "Can't open file: " << kBpfGpuMemTotalMap;
        return false;
    }

    auto res = map.readValue(kBpfKeyGpuUsage);

    if (res.ok()) {
        gpu_mem = res.value();
    } else if (res.error().code() == ENOENT) {
        gpu_mem = 0;
    } else {
        LOG(ERROR) << "Invalid file format: " << kBpfGpuMemTotalMap;
        return false;
    }

    if (size) {
        *size = gpu_mem / 1024;
    }
    return true;
#else
    if (size) {
        *size = 0;
    }
    return false;
#endif
}

bool ReadGpuTotalUsageKb(uint64_t* size) {
    // gpu_mem_total tracepoint defines PID 0 as global total
    // GPU ID 0 suffices for current android devices.
    // This will need to check all GPU IDs in future if more than
    // one is GPU device is present on the device.
    return ReadProcessGpuUsageKb(0, 0, size);
}

bool ReadKernelCmaUsageKb(uint64_t* size, const std::string& cma_stats_sysfs_path) {
    uint64_t totalKernelCmaUsageKb = 0;
    std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(cma_stats_sysfs_path.c_str()), closedir);
    if (!dir) {
        static bool missingDirLogged = false;
        // Kernels prior to 6.12 may not have this directory available, so log an error only once
        // to avoid spamming the logs in that scenario.
        //
        // Log all other types of errors.
        if (errno == ENOENT) {
            if (missingDirLogged) {
                return false;
            }
            missingDirLogged = true;
        }
        PLOG(ERROR) << "Failed to open CMA sysfs stats directory: " << cma_stats_sysfs_path;
        return false;
    }

    struct dirent* dent;
    while ((dent = readdir(dir.get()))) {
        if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, "..")) continue;

        uint64_t allocPagesSuccess;
        std::string allocPagesSuccessPath = ::android::base::StringPrintf(
                                                "%s/%s/alloc_pages_success",
                                                cma_stats_sysfs_path.c_str(),
                                                dent->d_name);
        if (!ReadSysfsFile(allocPagesSuccessPath, &allocPagesSuccess)) return false;

        uint64_t releasePagesSuccess;
        std::string releasePagesSuccessPath = ::android::base::StringPrintf(
                                                "%s/%s/release_pages_success",
                                                cma_stats_sysfs_path.c_str(),
                                                dent->d_name);
        if (!ReadSysfsFile(releasePagesSuccessPath, &releasePagesSuccess)) return false;

        totalKernelCmaUsageKb += allocPagesSuccess - releasePagesSuccess;
    }

    totalKernelCmaUsageKb *= getpagesize() / 1024;
    if (size) {
        *size = totalKernelCmaUsageKb;
    }

    return true;
}

std::optional<uint64_t> ParseSizeToBytes(const std::string& str) {
    if (str.empty()) {
        return std::nullopt;
    }

    static const std::regex sizeRegex(R"(\s*(0|[1-9][0-9]*)\s*(B|[KMG](?:i?B)?)\s*)",
                                      std::regex::icase);
    std::smatch match;

    if (std::regex_match(str, match, sizeRegex)) {
        uint64_t value;
        if (android::base::ParseUint(match[1].str(), &value)) {
            std::string unitStr = match[2].str();
            std::transform(unitStr.begin(), unitStr.end(), unitStr.begin(), ::toupper);

            if (unitStr == "GIB" || unitStr == "GI") {
                return value * 1024 * 1024 * 1024;
            } else if (unitStr == "GB" || unitStr == "G") {
                return value * 1000 * 1000 * 1000;
            } else if (unitStr == "MIB" || unitStr == "MI") {
                return value * 1024 * 1024;
            } else if (unitStr == "MB" || unitStr == "M") {
                return value * 1000 * 1000;
            } else if (unitStr == "KIB" || unitStr == "KI") {
                return value * 1024;
            } else if (unitStr == "KB" || unitStr == "K") {
                return value * 1000;
            } else if (unitStr == "B") {
                return value;
            }
        }
    }

    return std::nullopt;
}

static bool getSlabCacheTotalMemUsage(const std::string& name,
                                      const std::vector<std::string>& slabCells, int32_t* out) {
    const int kPageSize = getpagesize();
    const unsigned int kPagesPerSlabIdx = 5;
    const unsigned int kNumSlabsIdx = 14;

    unsigned long pagesPerSlab = strtoul(slabCells[kPagesPerSlabIdx].c_str(), nullptr, 10);
    if (pagesPerSlab == ULONG_MAX) {
        PLOG(ERROR) << "Failed to parse pages per slab cell for slab cache: " << name;
        return false;
    }

    unsigned long numSlabs = strtoul(slabCells[kNumSlabsIdx].c_str(), nullptr, 10);
    if (numSlabs == ULONG_MAX) {
        PLOG(ERROR) << "Failed to parse number of slabs for slab cache: " << name;
        return false;
    }

    *out = (kPageSize * pagesPerSlab * numSlabs) / 1024;
    return true;
}

static bool validateSlabInfoVersion(const std::unique_ptr<FILE, decltype(&fclose)>& fp) {
    char* versionLine = nullptr;
    size_t size = 0;

    if (getline(&versionLine, &size, fp.get()) < 0) {
        PLOG(ERROR) << "Failed to read slabinfo header";
        return false;
    }

    const unsigned int kSupportedMajorVersion = 2;
    const unsigned int kSupportedMinorVersion = 1;
    unsigned int majorVersion, minorVersion;
    bool ret = true;

    if (sscanf(versionLine, "slabinfo - version: %d.%d", &majorVersion, &minorVersion) != 2) {
        LOG(ERROR) << "Failed to parse slabinfo header";
        ret = false;
        goto out;
    }

    // We only support slabinfo - version 2.1 at the moment.
    if (!((majorVersion == kSupportedMajorVersion) && (minorVersion == kSupportedMinorVersion))) {
        LOG(ERROR) << "Current slabinfo version: " << majorVersion << "." << minorVersion
                   << " is not supported";
        ret = false;
        goto out;
    }

    ret = true;
out:
    free(versionLine);
    return ret;
}

bool ReadSlabInfo(std::unordered_map<std::string, SlabCacheStats>* out,
                  const std::string& slabInfoPath) {
    if (out == nullptr) {
        LOG(ERROR) << "ReadSlabInfo out parameter is NULL";
        return false;
    }
    out->clear();

    auto slabInfoFp = std::unique_ptr<FILE, decltype(&fclose)>{fopen(slabInfoPath.c_str(), "re"),
                                                               fclose};
    if (slabInfoFp == nullptr) {
        PLOG(ERROR) << "Failed to read slabinfo file: " << slabInfoPath;
        return false;
    }

    if (!validateSlabInfoVersion(slabInfoFp)) {
        return false;
    }

    char* line = nullptr;
    size_t size = 0;
    // Discard second line, since it's not useful.
    if (getline(&line, &size, slabInfoFp.get()) < 0) {
        return false;
    }

    const unsigned int kSlabInfoNrCells = 16;
    const unsigned int kSlabCacheNameIdx = 0;
    bool ret = true;
    while(getline(&line, &size, slabInfoFp.get()) > 0) {
        std::vector<std::string> cells = ::android::base::Tokenize(std::string(line), " ");
        if (cells.size() != kSlabInfoNrCells) {
            LOG(ERROR) << "Number of entries per-row: " << cells.size() << " does not match "
                       << "expected number of entries: " << kSlabInfoNrCells;
            ret = false;
            break;
        }

        std::string name = cells[kSlabCacheNameIdx];
        SlabCacheStats stats;
        if (!getSlabCacheTotalMemUsage(name, cells, &stats.totalMemUsageKb)) {
            ret = false;
            break;
        }

        const auto& iter = out->find(name);
        if (iter == out->end()) {
            out->insert({name, stats});
        } else {
            // Linux kernel commit 4c39529663b93 ("slab: Warn on duplicate cache names when
            // DEBUG_VM=y) admits that this is a possible scenario. For now, we'll just clump
            // slab caches with duplicate names together.
            iter->second.totalMemUsageKb += stats.totalMemUsageKb;
        }
    }
    free(line);
    return ret;
}

}  // namespace meminfo
}  // namespace android
