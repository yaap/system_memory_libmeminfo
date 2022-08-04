/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <meminfo/procmeminfo.h>

using ::android::meminfo::Vma;

struct VmaInfo {
    Vma vma;
    bool is_bss;
    uint32_t count;

    VmaInfo() = default;
    VmaInfo(const Vma& v) : vma(v), is_bss(false), count(1) {}
    VmaInfo(const Vma& v, bool bss) : vma(v), is_bss(bss), count(1) {}
    VmaInfo(const Vma& v, const std::string& name, bool bss) : vma(v), is_bss(bss), count(1) {
        vma.name = name;
    }
};

// Global options
static std::string g_filename = "";
static bool g_merge_by_names = false;
static bool g_terse = false;
static bool g_verbose = false;
static bool g_show_addr = false;
static bool g_quiet = false;
static pid_t g_pid = -1;

static VmaInfo g_total;
static std::vector<VmaInfo> g_vmas;
static std::map<std::string, VmaInfo> g_vmas_name_map;

[[noreturn]] static void usage(const char* progname, int exit_status) {
    fprintf(stderr,
            "%s [-aqtv] [-f FILE] PID\n"
            "-a\taddresses (show virtual memory map)\n"
            "-q\tquiet (don't show error if map could not be read)\n"
            "-t\tterse (show only items with private pages)\n"
            "-v\tverbose (don't coalesce maps with the same name)\n"
            "-f\tFILE (read from input from FILE instead of PID)\n",
            progname);

    exit(exit_status);
}

static bool is_library(const std::string& name) {
    return (name.size() > 4) && (name[0] == '/') && ::android::base::EndsWith(name, ".so");
}

static bool insert_before(const VmaInfo& a, const VmaInfo& b) {
    if (g_show_addr) {
        return (a.vma.start < b.vma.start || (a.vma.start == b.vma.start && a.vma.end < b.vma.end));
    }

    return strcmp(a.vma.name.c_str(), b.vma.name.c_str()) < 0;
}

static void infer_vma_name(VmaInfo& current, const VmaInfo& recent) {
    if (current.vma.name.empty()) {
        if (recent.vma.end == current.vma.start && is_library(recent.vma.name)) {
            current.vma.name = recent.vma.name;
            current.is_bss = true;
        } else {
            current.vma.name = "[anon]";
        }
    }
}

static void collect_vma(const Vma& vma) {
    static VmaInfo recent;
    VmaInfo current(vma);
    if (g_vmas.empty()) {
        g_vmas.emplace_back(current);
        recent = current;
        return;
    }

    infer_vma_name(current, recent);
    recent = current;

    std::vector<VmaInfo>::iterator it;
    for (it = g_vmas.begin(); it != g_vmas.end(); it++) {
        if (insert_before(current, *it)) {
            g_vmas.insert(it, current);
            break;
        }
    }

    if (it == g_vmas.end()) {
        g_vmas.emplace_back(current);
    }
}

static void collect_vma_merge_by_names(const Vma& vma) {
    static VmaInfo recent;
    VmaInfo current(vma);
    if (g_vmas_name_map.empty()) {
        g_vmas_name_map.emplace(vma.name, vma);
        recent = current;
        return;
    }

    infer_vma_name(current, recent);
    recent = current;

    auto iter = g_vmas_name_map.find(current.vma.name);
    if (iter == g_vmas_name_map.end()) {
        g_vmas_name_map.emplace(current.vma.name, current);
        return;
    }
    VmaInfo& match = iter->second;
    match.vma.usage.vss += current.vma.usage.vss;
    match.vma.usage.rss += current.vma.usage.rss;
    match.vma.usage.pss += current.vma.usage.pss;

    match.vma.usage.shared_clean += current.vma.usage.shared_clean;
    match.vma.usage.shared_dirty += current.vma.usage.shared_dirty;
    match.vma.usage.private_clean += current.vma.usage.private_clean;
    match.vma.usage.private_dirty += current.vma.usage.private_dirty;
    match.vma.usage.swap += current.vma.usage.swap;
    match.vma.usage.swap_pss += current.vma.usage.swap_pss;

    match.vma.usage.anon_huge_pages += current.vma.usage.anon_huge_pages;
    match.vma.usage.shmem_pmd_mapped += current.vma.usage.shmem_pmd_mapped;
    match.vma.usage.file_pmd_mapped += current.vma.usage.file_pmd_mapped;
    match.vma.usage.shared_hugetlb += current.vma.usage.shared_hugetlb;
    match.vma.usage.private_hugetlb += current.vma.usage.shared_hugetlb;

    match.is_bss &= current.is_bss;
}

static void print_header() {
    const char* addr1 = g_show_addr ? "           start              end " : "";
    const char* addr2 = g_show_addr ? "            addr             addr " : "";

    printf("%s virtual                     shared   shared  private  private                   "
           "Anon      Shmem     File       Shared   Private\n",
           addr1);
    printf("%s    size      RSS      PSS    clean    dirty    clean    dirty     swap  swapPSS "
           "HugePages PmdMapped PmdMapped  Hugetlb  Hugetlb",
           addr2);
    if (!g_verbose && !g_show_addr) {
        printf("   # ");
    }
    if (g_verbose) {
        printf(" flags ");
    }
    printf(" object\n");
}

static void print_divider() {
    if (g_show_addr) {
        printf("-------- -------- ");
    }
    printf("-------- -------- -------- -------- -------- -------- -------- -------- -------- "
           "--------- --------- --------- -------- -------- ");
    if (!g_verbose && !g_show_addr) {
        printf("---- ");
    }
    if (g_verbose) {
        printf("------ ");
    }
    printf("------------------------------\n");
}

static void print_vmainfo(const VmaInfo& v, bool total) {
    if (g_show_addr) {
        if (total) {
            printf("                                  ");
        } else {
            printf("%16" PRIx64 " %16" PRIx64 " ", v.vma.start, v.vma.end);
        }
    }
    printf("%8" PRIu64 " %8" PRIu64 " %8" PRIu64 " %8" PRIu64 " %8" PRIu64 " %8" PRIu64 " %8" PRIu64
           " %8" PRIu64 " %8" PRIu64 " %9" PRIu64 " %9" PRIu64 " %9" PRIu64 " %8" PRIu64
           " %8" PRIu64 " ",
           v.vma.usage.vss, v.vma.usage.rss, v.vma.usage.pss, v.vma.usage.shared_clean,
           v.vma.usage.shared_dirty, v.vma.usage.private_clean, v.vma.usage.private_dirty,
           v.vma.usage.swap, v.vma.usage.swap_pss, v.vma.usage.anon_huge_pages,
           v.vma.usage.shmem_pmd_mapped, v.vma.usage.file_pmd_mapped, v.vma.usage.shared_hugetlb,
           v.vma.usage.private_hugetlb);
    if (!g_verbose && !g_show_addr) {
        printf("%4" PRIu32 " ", v.count);
    }
    if (g_verbose) {
        if (total) {
            printf("       ");
        } else {
            std::string flags_str("---");
            if (v.vma.flags & PROT_READ) flags_str[0] = 'r';
            if (v.vma.flags & PROT_WRITE) flags_str[1] = 'w';
            if (v.vma.flags & PROT_EXEC) flags_str[2] = 'x';

            printf("%6s ", flags_str.c_str());
        }
    }
}

static int showmap(void) {
    bool success;
    if (!g_merge_by_names) {
        success = ::android::meminfo::ForEachVmaFromFile(g_filename, collect_vma);
    } else {
        success = ::android::meminfo::ForEachVmaFromFile(g_filename, collect_vma_merge_by_names);
        g_vmas.reserve(g_vmas_name_map.size());
        // VMAs will be returned in lexicographical order of names.
        for (const auto& entry : g_vmas_name_map) {
            g_vmas.emplace_back(entry.second);
        }
    }

    if (!success) {
        if (!g_quiet) {
            fprintf(stderr, "Failed to parse file %s\n", g_filename.c_str());
        }
        return 1;
    }

    print_header();
    print_divider();

    for (const auto& v : g_vmas) {
        g_total.vma.usage.vss += v.vma.usage.vss;
        g_total.vma.usage.rss += v.vma.usage.rss;
        g_total.vma.usage.pss += v.vma.usage.pss;

        g_total.vma.usage.private_clean += v.vma.usage.private_clean;
        g_total.vma.usage.private_dirty += v.vma.usage.private_dirty;
        g_total.vma.usage.shared_clean += v.vma.usage.shared_clean;
        g_total.vma.usage.shared_dirty += v.vma.usage.shared_dirty;

        g_total.vma.usage.swap += v.vma.usage.swap;
        g_total.vma.usage.swap_pss += v.vma.usage.swap_pss;
        g_total.count += v.count;

        if (g_terse && !(v.vma.usage.private_dirty || v.vma.usage.private_clean)) {
            continue;
        }

        print_vmainfo(v, false);
        printf("%s%s\n", v.vma.name.c_str(), v.is_bss ? " [bss]" : "");
    }

    print_divider();
    print_header();
    print_divider();

    print_vmainfo(g_total, true);
    printf("TOTAL\n");

    return 0;
}

int main(int argc, char* argv[]) {
    signal(SIGPIPE, SIG_IGN);
    struct option longopts[] = {
            {"help", no_argument, nullptr, 'h'},
            {0, 0, nullptr, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "tvaqf:h", longopts, nullptr)) != -1) {
        switch (opt) {
            case 't':
                g_terse = true;
                break;
            case 'a':
                g_show_addr = true;
                break;
            case 'v':
                g_verbose = true;
                break;
            case 'q':
                g_quiet = true;
                break;
            case 'f':
                g_filename = optarg;
                break;
            case 'h':
                usage(argv[0], EXIT_SUCCESS);
            default:
                usage(argv[0], EXIT_FAILURE);
        }
    }

    if (g_filename.empty()) {
        if ((argc - 1) < optind) {
            fprintf(stderr, "Invalid arguments: Must provide <pid> at the end\n");
            usage(argv[0], EXIT_FAILURE);
        }

        g_pid = atoi(argv[optind]);
        if (g_pid <= 0) {
            fprintf(stderr, "Invalid process id %s\n", argv[optind]);
            usage(argv[0], EXIT_FAILURE);
        }

        g_filename = ::android::base::StringPrintf("/proc/%d/smaps", g_pid);
    }

    g_merge_by_names = !g_verbose && !g_show_addr;
    return showmap();
}
