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

#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <meminfo/procmeminfo.h>

using ::android::meminfo::EscapeCsvString;
using ::android::meminfo::EscapeJsonString;
using ::android::meminfo::Format;
using ::android::meminfo::GetFormat;
using ::android::meminfo::Vma;

// Global options
static std::string g_filename;
static bool g_merge_by_names = false;
static bool g_terse = false;
static bool g_verbose = false;
static bool g_show_addr = false;
static bool g_quiet = false;
static pid_t g_pid = -1;

static std::string get_vma_name(const Vma& vma, bool total, bool is_bss) {
    if (total) {
        return std::string("TOTAL");
    }
    std::string vmaName(vma.name);
    if (is_bss) {
        vmaName += std::string(" [bss]");
    }
    return vmaName;
}

static std::string get_flags(const Vma& vma, bool total) {
    std::string flags_str("---");
    if (g_verbose && !total) {
        if (vma.flags & PROT_READ) flags_str[0] = 'r';
        if (vma.flags & PROT_WRITE) flags_str[1] = 'w';
        if (vma.flags & PROT_EXEC) flags_str[2] = 'x';
    }
    return flags_str;
}

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

    void to_raw(std::ostream&, bool) const;
    void to_csv(std::ostream&, bool) const;
    void to_json(std::ostream&, bool) const;
};

void VmaInfo::to_raw(std::ostream& output, bool total) const {
    if (g_show_addr) {
        if (total) {
            output << "                                  ";
        } else {
            output << std::hex << std::setw(16) << vma.start << " " << std::setw(16) << vma.end
                   << " " << std::dec;
        }
    }
    // clang-format off
    output << std::setw(8) << vma.usage.vss << " "
           << std::setw(8) << vma.usage.rss << " "
           << std::setw(8) << vma.usage.pss << " "
           << std::setw(8) << vma.usage.shared_clean << " "
           << std::setw(8) << vma.usage.shared_dirty << " "
           << std::setw(8) << vma.usage.private_clean << " "
           << std::setw(8) << vma.usage.private_dirty << " "
           << std::setw(8) << vma.usage.swap << " "
           << std::setw(8) << vma.usage.swap_pss << " "
           << std::setw(9) << vma.usage.anon_huge_pages << " "
           << std::setw(9) << vma.usage.shmem_pmd_mapped << " "
           << std::setw(9) << vma.usage.file_pmd_mapped << " "
           << std::setw(8) << vma.usage.shared_hugetlb << " "
           << std::setw(8) << vma.usage.private_hugetlb << " ";
    // clang-format on
    if (!g_verbose && !g_show_addr) {
        output << std::setw(4) << count << " ";
    }
    if (g_verbose) {
        if (total) {
            output << "       ";
        } else {
            output << std::setw(6) << get_flags(vma, total) << " ";
        }
    }
    output << get_vma_name(vma, total, is_bss) << "\n";
}

void VmaInfo::to_csv(std::ostream& output, bool total) const {
    // clang-format off
    output << vma.usage.vss
           << "," << vma.usage.rss
           << "," << vma.usage.pss
           << "," << vma.usage.shared_clean
           << "," << vma.usage.shared_dirty
           << "," << vma.usage.private_clean
           << "," << vma.usage.private_dirty
           << "," << vma.usage.swap
           << "," << vma.usage.swap_pss
           << "," << vma.usage.anon_huge_pages
           << "," << vma.usage.shmem_pmd_mapped
           << "," << vma.usage.file_pmd_mapped
           << "," << vma.usage.shared_hugetlb
           << "," << vma.usage.private_hugetlb;
    // clang-format on
    if (g_show_addr) {
        output << ",";
        if (total) {
            output << ",";
        } else {
            output << std::hex << vma.start << "," << vma.end << std::dec;
        }
    }
    if (!g_verbose && !g_show_addr) {
        output << "," << count;
    }
    if (g_verbose) {
        output << ",";
        if (!total) {
            output << EscapeCsvString(get_flags(vma, total));
        }
    }
    output << "," << EscapeCsvString(get_vma_name(vma, total, is_bss)) << "\n";
}

void VmaInfo::to_json(std::ostream& output, bool total) const {
    // clang-format off
    output << "{\"virtual size\":" << vma.usage.vss
           << ",\"RSS\":" << vma.usage.rss
           << ",\"PSS\":" << vma.usage.pss
           << ",\"shared clean\":" << vma.usage.shared_clean
           << ",\"shared dirty\":" << vma.usage.shared_dirty
           << ",\"private clean\":" << vma.usage.private_clean
           << ",\"private dirty\":" << vma.usage.private_dirty
           << ",\"swap\":" << vma.usage.swap
           << ",\"swapPSS\":" << vma.usage.swap_pss
           << ",\"Anon HugePages\":" << vma.usage.anon_huge_pages
           << ",\"Shmem PmdMapped\":" << vma.usage.shmem_pmd_mapped
           << ",\"File PmdMapped\":" << vma.usage.file_pmd_mapped
           << ",\"Shared Hugetlb\":" << vma.usage.shared_hugetlb
           << ",\"Private Hugetlb\":" << vma.usage.private_hugetlb;
    // clang-format on
    if (g_show_addr) {
        if (total) {
            output << ",\"start addr\":\"\",\"end addr\":\"\"";
        } else {
            output << ",\"start addr\":\"" << std::hex << vma.start << "\",\"end addr\":\""
                   << vma.end << "\"" << std::dec;
        }
    }
    if (!g_verbose && !g_show_addr) {
        output << ",\"#\":" << count;
    }
    if (g_verbose) {
        output << ",\"flags\":" << EscapeJsonString(get_flags(vma, total));
    }
    output << ",\"object\":" << EscapeJsonString(get_vma_name(vma, total, is_bss)) << "}";
}

static VmaInfo g_total;
static std::vector<VmaInfo> g_vmas;
static std::map<std::string, VmaInfo> g_vmas_name_map;

[[noreturn]] static void usage(const char* progname, int exit_status) {
    std::cerr << progname << " [-aqtv] [-f FILE] PID\n"
              << "-a\taddresses (show virtual memory map)\n"
              << "-q\tquiet (don't show error if map could not be read)\n"
              << "-t\tterse (show only items with private pages)\n"
              << "-v\tverbose (don't coalesce maps with the same name)\n"
              << "-f\tFILE (read from input from FILE instead of PID)\n"
              << "-o\t[raw][json][csv] Print output in the specified format.\n"
              << "  \tDefault output format is raw text.)\n";

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

static void print_header(std::ostream& output) {
    if (g_show_addr) {
        output << "           start              end ";
    }
    output << " virtual                     shared   shared  private  private                   "
              "Anon      Shmem     File       Shared   Private\n";

    if (g_show_addr) {
        output << "            addr             addr ";
    }
    output << "    size      RSS      PSS    clean    dirty    clean    dirty     swap  swapPSS "
              "HugePages PmdMapped PmdMapped  Hugetlb  Hugetlb";
    if (!g_verbose && !g_show_addr) {
        output << "   # ";
    }
    if (g_verbose) {
        output << " flags ";
    }
    output << " object\n";
}

static void print_divider(std::ostream& output) {
    if (g_show_addr) {
        output << "-------- -------- ";
    }
    output << "-------- -------- -------- -------- -------- -------- -------- -------- -------- "
           << "--------- --------- --------- -------- -------- ";
    if (!g_verbose && !g_show_addr) {
        output << "---- ";
    }
    if (g_verbose) {
        output << "------ ";
    }
    output << "------------------------------\n";
}

static int showmap(Format format) {
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
            std::cerr << "Failed to parse file " << g_filename << "\n";
        }
        return 1;
    }

    // Headers
    switch (format) {
        case Format::RAW:
            print_header(std::cout);
            print_divider(std::cout);
            break;
        case Format::CSV:
            std::cout << "\"virtual size\",\"RSS\",\"PSS\",\"shared clean\",\"shared "
                         "dirty\",\"private "
                         "clean\",\"private dirty\",\"swap\",\"swapPSS\",\"Anon "
                         "HugePages\",\"Shmem "
                         "PmdMapped\",\"File PmdMapped\",\"Shared Hugetlb\",\"Private "
                         "Hugetlb\"";
            if (g_show_addr) {
                std::cout << ",\"start addr\",\"end addr\"";
            }
            if (!g_verbose && !g_show_addr) {
                std::cout << ",\"#\"";
            }
            if (g_verbose) {
                std::cout << ",\"flags\"";
            }
            std::cout << ",\"object\"\n";
            break;
        case Format::JSON:
            std::cout << "[";
            break;
        default:
            break;
    }

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

        switch (format) {
            case Format::RAW:
                v.to_raw(std::cout, false);
                break;
            case Format::CSV:
                v.to_csv(std::cout, false);
                break;
            case Format::JSON:
                v.to_json(std::cout, false);
                std::cout << ",";
                break;
            default:
                break;
        }
    }

    // Output total vma info
    switch (format) {
        case Format::RAW:
            print_divider(std::cout);
            print_header(std::cout);
            print_divider(std::cout);
            g_total.to_raw(std::cout, true);
            break;
        case Format::CSV:
            g_total.to_csv(std::cout, true);
            break;
        case Format::JSON:
            g_total.to_json(std::cout, true);
            std::cout << "]\n";
            break;
        default:
            break;
    }

    return 0;
}

int main(int argc, char* argv[]) {
    signal(SIGPIPE, SIG_IGN);
    struct option longopts[] = {
            {"help", no_argument, nullptr, 'h'},
            {0, 0, nullptr, 0},
    };

    Format format = Format::RAW;
    int opt;
    while ((opt = getopt_long(argc, argv, "tvaqf:o:h", longopts, nullptr)) != -1) {
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
            case 'o':
                format = GetFormat(optarg);
                if (format == Format::INVALID) {
                    std::cerr << "Invalid format.\n";
                    usage(argv[0], EXIT_FAILURE);
                }
                break;
            case 'h':
                usage(argv[0], EXIT_SUCCESS);
            default:
                usage(argv[0], EXIT_FAILURE);
        }
    }

    if (g_filename.empty()) {
        if ((argc - 1) < optind) {
            std::cerr << "Invalid arguments: Must provide <pid> at the end\n";
            usage(argv[0], EXIT_FAILURE);
        }

        g_pid = atoi(argv[optind]);
        if (g_pid <= 0) {
            std::cerr << "Invalid process id " << argv[optind] << "\n";
            usage(argv[0], EXIT_FAILURE);
        }

        g_filename = ::android::base::StringPrintf("/proc/%d/smaps", g_pid);
    }

    g_merge_by_names = !g_verbose && !g_show_addr;
    return showmap(format);
}
