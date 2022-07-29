/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <inttypes.h>
#include <linux/oom.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <set>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/parseint.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <meminfo/procmeminfo.h>
#include <meminfo/sysmeminfo.h>

#include <smapinfo.h>

namespace android {
namespace smapinfo {

using ::android::base::StringPrintf;
using ::android::meminfo::MemUsage;
using ::android::meminfo::ProcMemInfo;

enum SortOrder { BY_PSS = 0, BY_RSS, BY_USS, BY_VSS, BY_SWAP, BY_OOMADJ };

struct ProcessRecord {
  public:
    ProcessRecord(pid_t pid, bool get_wss, uint64_t pgflags, uint64_t pgflags_mask,
                  bool get_cmdline, bool get_oomadj, std::stringstream& err)
        : pid_(-1),
          cmdline_(""),
          oomadj_(OOM_SCORE_ADJ_MAX + 1),
          proportional_swap_(0),
          unique_swap_(0),
          zswap_(0) {
        std::unique_ptr<ProcMemInfo> procmem =
                std::make_unique<ProcMemInfo>(pid, get_wss, pgflags, pgflags_mask);
        if (procmem == nullptr) {
            err << "Failed to create ProcMemInfo for: " << pid << std::endl;
            return;
        }

        // cmdline_ only needs to be populated if this record will be used by procrank/librank.
        if (get_cmdline) {
            std::string fname = StringPrintf("/proc/%d/cmdline", pid);
            if (!::android::base::ReadFileToString(fname, &cmdline_)) {
                std::cerr << "Failed to read cmdline from: " << fname << std::endl;
                cmdline_ = "<unknown>";
            }
            // We deliberately don't read the /proc/<pid>/cmdline file directly into 'cmdline_'
            // because some processes have cmdlines that end with "0x00 0x0A 0x00",
            // e.g. xtra-daemon, lowi-server.
            // The .c_str() assignment takes care of trimming the cmdline at the first 0x00. This is
            // how the original procrank worked (luckily).
            cmdline_.resize(strlen(cmdline_.c_str()));
        }

        // oomadj_ only needs to be populated if this record will be used by procrank.
        if (get_oomadj) {
            std::string fname = StringPrintf("/proc/%d/oom_score_adj", pid);
            std::string oom_score;
            if (!::android::base::ReadFileToString(fname, &oom_score)) {
                std::cerr << "Failed to read oom_score_adj file: " << fname << std::endl;
                return;
            }
            if (!::android::base::ParseInt(::android::base::Trim(oom_score), &oomadj_)) {
                std::cerr << "Failed to parse oomadj from: " << fname << std::endl;
                return;
            }
        }

        usage_or_wss_ = get_wss ? procmem->Wss() : procmem->Usage();
        swap_offsets_ = procmem->SwapOffsets();
        pid_ = pid;
    }

    bool valid() const { return pid_ != -1; }

    void CalculateSwap(const std::vector<uint16_t>& swap_offset_array,
                       float zram_compression_ratio) {
        for (auto& off : swap_offsets_) {
            proportional_swap_ += getpagesize() / swap_offset_array[off];
            unique_swap_ += swap_offset_array[off] == 1 ? getpagesize() : 0;
            zswap_ = proportional_swap_ * zram_compression_ratio;
        }
    }

    // Getters
    pid_t pid() const { return pid_; }
    const std::string& cmdline() const { return cmdline_; }
    int32_t oomadj() const { return oomadj_; }
    uint64_t proportional_swap() const { return proportional_swap_; }
    uint64_t unique_swap() const { return unique_swap_; }
    uint64_t zswap() const { return zswap_; }

    // Wrappers to ProcMemInfo
    const std::vector<uint64_t>& SwapOffsets() const { return swap_offsets_; }
    // show_wss may be used to return differentiated output in the future.
    const MemUsage& Usage([[maybe_unused]] bool show_wss) const { return usage_or_wss_; }

  private:
    pid_t pid_;
    std::string cmdline_;
    int32_t oomadj_;
    uint64_t proportional_swap_;
    uint64_t unique_swap_;
    uint64_t zswap_;
    MemUsage usage_or_wss_;
    std::vector<uint64_t> swap_offsets_;
};

bool get_all_pids(std::set<pid_t>* pids) {
    pids->clear();
    std::unique_ptr<DIR, int (*)(DIR*)> procdir(opendir("/proc"), closedir);
    if (!procdir) return false;

    struct dirent* dir;
    pid_t pid;
    while ((dir = readdir(procdir.get()))) {
        if (!::android::base::ParseInt(dir->d_name, &pid)) continue;
        pids->insert(pid);
    }
    return true;
}

static bool count_swap_offsets(const ProcessRecord& proc, std::vector<uint16_t>& swap_offset_array,
                               std::stringstream& err) {
    const std::vector<uint64_t>& swp_offs = proc.SwapOffsets();
    for (auto& off : swp_offs) {
        if (off >= swap_offset_array.size()) {
            err << "swap offset " << off << " is out of bounds for process: " << proc.pid()
                << std::endl;
            return false;
        }
        if (swap_offset_array[off] == USHRT_MAX) {
            err << "swap offset " << off << " ref count overflow in process: " << proc.pid()
                << std::endl;
            return false;
        }
        swap_offset_array[off]++;
    }
    return true;
}

struct procrank_params {
    // Calculated total memory usage across all processes in the system.
    uint64_t total_pss;
    uint64_t total_uss;
    uint64_t total_swap;
    uint64_t total_pswap;
    uint64_t total_uswap;
    uint64_t total_zswap;

    // Print options.
    bool show_oomadj;
    bool show_wss;
    bool swap_enabled;
    bool zram_enabled;

    // If zram is enabled, the compression ratio is zram used / swap used.
    float zram_compression_ratio;
};

static std::function<bool(ProcessRecord& a, ProcessRecord& b)> select_procrank_sort(
        struct procrank_params* params, int sort_order) {
    // Create sort function based on sort_order.
    std::function<bool(ProcessRecord & a, ProcessRecord & b)> proc_sort;
    switch (sort_order) {
        case (BY_OOMADJ):
            proc_sort = [&](ProcessRecord& a, ProcessRecord& b) { return a.oomadj() > b.oomadj(); };
            break;
        case (BY_RSS):
            proc_sort = [=](ProcessRecord& a, ProcessRecord& b) {
                return a.Usage(params->show_wss).rss > b.Usage(params->show_wss).rss;
            };
            break;
        case (BY_SWAP):
            proc_sort = [=](ProcessRecord& a, ProcessRecord& b) {
                return a.Usage(params->show_wss).swap > b.Usage(params->show_wss).swap;
            };
            break;
        case (BY_USS):
            proc_sort = [=](ProcessRecord& a, ProcessRecord& b) {
                return a.Usage(params->show_wss).uss > b.Usage(params->show_wss).uss;
            };
            break;
        case (BY_VSS):
            proc_sort = [=](ProcessRecord& a, ProcessRecord& b) {
                return a.Usage(params->show_wss).vss > b.Usage(params->show_wss).vss;
            };
            break;
        case (BY_PSS):
        default:
            proc_sort = [=](ProcessRecord& a, ProcessRecord& b) {
                return a.Usage(params->show_wss).pss > b.Usage(params->show_wss).pss;
            };
            break;
    }
    return proc_sort;
}

static bool populate_procrank_procs(struct procrank_params* params, uint64_t pgflags,
                                    uint64_t pgflags_mask, std::vector<uint16_t>& swap_offset_array,
                                    const std::set<pid_t>& pids, std::vector<ProcessRecord>* procs,
                                    std::stringstream& err) {
    // Mark each swap offset used by the process as we find them for calculating
    // proportional swap usage later.
    for (pid_t pid : pids) {
        ProcessRecord proc(pid, params->show_wss, pgflags, pgflags_mask, true, params->show_oomadj,
                           err);

        if (!proc.valid()) {
            // Check to see if the process is still around, skip the process if the proc
            // directory is inaccessible. It was most likely killed while creating the process
            // record.
            std::string procdir = StringPrintf("/proc/%d", pid);
            if (access(procdir.c_str(), F_OK | R_OK)) continue;

            // Warn if we failed to gather process stats even while it is still alive.
            // Return success here, so we continue to print stats for other processes.
            err << "warning: failed to create process record for: " << pid << std::endl;
            continue;
        }

        // Skip processes with no memory mappings.
        uint64_t vss = proc.Usage(params->show_wss).vss;
        if (vss == 0) continue;

        // Collect swap_offset counts from all processes in 1st pass.
        if (!params->show_wss && params->swap_enabled &&
            !count_swap_offsets(proc, swap_offset_array, err)) {
            err << "Failed to count swap offsets for process: " << pid << std::endl;
            err << "Failed to read all pids from the system" << std::endl;
            return false;
        }

        procs->emplace_back(std::move(proc));
    }
    return true;
}

static void print_procrank_header(struct procrank_params* params, std::stringstream& out) {
    out << StringPrintf("%5s  ", "PID");
    if (params->show_oomadj) {
        out << StringPrintf("%5s  ", "oom");
    }

    if (params->show_wss) {
        out << StringPrintf("%7s  %7s  %7s  ", "WRss", "WPss", "WUss");
    } else {
        // Swap statistics here, as working set pages by definition shouldn't end up in swap.
        out << StringPrintf("%8s  %7s  %7s  %7s  ", "Vss", "Rss", "Pss", "Uss");
        if (params->swap_enabled) {
            out << StringPrintf("%7s  %7s  %7s  ", "Swap", "PSwap", "USwap");
            if (params->zram_enabled) {
                out << StringPrintf("%7s  ", "ZSwap");
            }
        }
    }

    out << "cmdline";
}

static void print_procrank_divider(struct procrank_params* params, std::stringstream& out) {
    out << StringPrintf("%5s  ", "");
    if (params->show_oomadj) {
        out << StringPrintf("%5s  ", "");
    }

    if (params->show_wss) {
        out << StringPrintf("%7s  %7s  %7s  ", "", "------", "------");
    } else {
        out << StringPrintf("%8s  %7s  %7s  %7s  ", "", "", "------", "------");
        if (params->swap_enabled) {
            out << StringPrintf("%7s  %7s  %7s  ", "------", "------", "------");
            if (params->zram_enabled) {
                out << StringPrintf("%7s  ", "------");
            }
        }
    }

    out << StringPrintf("%s", "------");
}

static void print_procrank_processrecord(struct procrank_params* params, ProcessRecord& proc,
                                         std::stringstream& out) {
    out << StringPrintf("%5d  ", proc.pid());
    if (params->show_oomadj) {
        out << StringPrintf("%5d  ", proc.oomadj());
    }

    if (params->show_wss) {
        out << StringPrintf("%6" PRIu64 "K  %6" PRIu64 "K  %6" PRIu64 "K  ",
                            proc.Usage(params->show_wss).rss / 1024,
                            proc.Usage(params->show_wss).pss / 1024,
                            proc.Usage(params->show_wss).uss / 1024);
    } else {
        out << StringPrintf(
                "%7" PRIu64 "K  %6" PRIu64 "K  %6" PRIu64 "K  %6" PRIu64 "K  ",
                proc.Usage(params->show_wss).vss / 1024, proc.Usage(params->show_wss).rss / 1024,
                proc.Usage(params->show_wss).pss / 1024, proc.Usage(params->show_wss).uss / 1024);
        if (params->swap_enabled) {
            out << StringPrintf("%6" PRIu64 "K  ", proc.Usage(params->show_wss).swap / 1024);
            out << StringPrintf("%6" PRIu64 "K  ", proc.proportional_swap() / 1024);
            out << StringPrintf("%6" PRIu64 "K  ", proc.unique_swap() / 1024);
            if (params->zram_enabled) {
                out << StringPrintf("%6" PRIu64 "K  ", (proc.zswap() / 1024));
            }
        }
    }
}

static void print_procrank_processes(struct procrank_params* params,
                                     std::vector<ProcessRecord>& procs,
                                     const std::vector<uint16_t>& swap_offset_array,
                                     std::stringstream& out) {
    for (auto& proc : procs) {
        params->total_pss += proc.Usage(params->show_wss).pss;
        params->total_uss += proc.Usage(params->show_wss).uss;
        if (!params->show_wss && params->swap_enabled) {
            proc.CalculateSwap(swap_offset_array, params->zram_compression_ratio);
            params->total_swap += proc.Usage(params->show_wss).swap;
            params->total_pswap += proc.proportional_swap();
            params->total_uswap += proc.unique_swap();
            if (params->zram_enabled) {
                params->total_zswap += proc.zswap();
            }
        }

        print_procrank_processrecord(params, proc, out);
        out << proc.cmdline() << std::endl;
    }
}

static void print_procrank_totals(struct procrank_params* params, std::stringstream& out) {
    out << StringPrintf("%5s  ", "");
    if (params->show_oomadj) {
        out << StringPrintf("%5s  ", "");
    }

    if (params->show_wss) {
        out << StringPrintf("%7s  %6" PRIu64 "K  %6" PRIu64 "K  ", "", params->total_pss / 1024,
                            params->total_uss / 1024);
    } else {
        out << StringPrintf("%8s  %7s  %6" PRIu64 "K  %6" PRIu64 "K  ", "", "",
                            params->total_pss / 1024, params->total_uss / 1024);
        if (params->swap_enabled) {
            out << StringPrintf("%6" PRIu64 "K  ", params->total_swap / 1024);
            out << StringPrintf("%6" PRIu64 "K  ", params->total_pswap / 1024);
            out << StringPrintf("%6" PRIu64 "K  ", params->total_uswap / 1024);
            if (params->zram_enabled) {
                out << StringPrintf("%6" PRIu64 "K  ", params->total_zswap / 1024);
            }
        }
    }
    out << "TOTAL";
}

static void print_procrank_sysmeminfo(struct procrank_params* params,
                                      const ::android::meminfo::SysMemInfo& smi,
                                      std::stringstream& out) {
    if (params->swap_enabled) {
        out << StringPrintf("ZRAM: %" PRIu64 "K physical used for %" PRIu64 "K in swap (%" PRIu64
                            "K total swap)",
                            smi.mem_zram_kb(), (smi.mem_swap_kb() - smi.mem_swap_free_kb()),
                            smi.mem_swap_kb())
            << std::endl;
    }

    out << StringPrintf(" RAM: %" PRIu64 "K total, %" PRIu64 "K free, %" PRIu64
                        "K buffers, %" PRIu64 "K cached, %" PRIu64 "K shmem, %" PRIu64 "K slab",
                        smi.mem_total_kb(), smi.mem_free_kb(), smi.mem_buffers_kb(),
                        smi.mem_cached_kb(), smi.mem_shmem_kb(), smi.mem_slab_kb());
}

bool procrank(uint64_t pgflags, uint64_t pgflags_mask, const std::set<pid_t>& pids, bool get_oomadj,
              bool get_wss, int sort_order, bool reverse_sort, std::stringstream& out,
              std::stringstream& err) {
    ::android::meminfo::SysMemInfo smi;
    if (!smi.ReadMemInfo()) {
        err << "Failed to get system memory info" << std::endl;
        return false;
    }

    struct procrank_params params = {
            .total_pss = 0,
            .total_uss = 0,
            .total_swap = 0,
            .total_pswap = 0,
            .total_uswap = 0,
            .total_zswap = 0,
            .show_oomadj = get_oomadj,
            .show_wss = get_wss,
            .swap_enabled = false,
            .zram_enabled = false,
            .zram_compression_ratio = 0.0,
    };

    // Figure out swap and zram.
    uint64_t swap_total = smi.mem_swap_kb() * 1024;
    params.swap_enabled = swap_total > 0;
    // Allocate the swap array.
    std::vector<uint16_t> swap_offset_array(swap_total / getpagesize() + 1, 0);
    if (params.swap_enabled) {
        params.zram_enabled = smi.mem_zram_kb() > 0;
        if (params.zram_enabled) {
            params.zram_compression_ratio = static_cast<float>(smi.mem_zram_kb()) /
                                            (smi.mem_swap_kb() - smi.mem_swap_free_kb());
        }
    }

    std::vector<ProcessRecord> procs;
    if (!populate_procrank_procs(&params, pgflags, pgflags_mask, swap_offset_array, pids, &procs,
                                 err)) {
        return false;
    }

    if (procs.empty()) {
        // This would happen in corner cases where procrank is being run to find KSM usage on a
        // system with no KSM and combined with working set determination as follows
        //   procrank -w -u -k
        //   procrank -w -s -k
        //   procrank -w -o -k
        out << "<empty>" << std::endl << std::endl;
        print_procrank_sysmeminfo(&params, smi, out);
        return true;
    }

    // Create sort function based on sort_order, default is PSS descending.
    std::function<bool(ProcessRecord & a, ProcessRecord & b)> proc_sort =
            select_procrank_sort(&params, sort_order);

    // Sort all process records, default is PSS descending.
    if (reverse_sort) {
        std::sort(procs.rbegin(), procs.rend(), proc_sort);
    } else {
        std::sort(procs.begin(), procs.end(), proc_sort);
    }

    // start dumping output in string stream
    print_procrank_header(&params, out);
    out << std::endl;

    // 2nd pass to calculate and get per process stats to add them up
    print_procrank_processes(&params, procs, swap_offset_array, out);

    // Add divider to output
    print_procrank_divider(&params, out);
    out << std::endl;

    // Add totals to output
    print_procrank_totals(&params, out);
    out << std::endl << std::endl;

    // Add system information at the end
    print_procrank_sysmeminfo(&params, smi, out);
    out << std::endl;

    return true;
}

}  // namespace smapinfo
}  // namespace android
