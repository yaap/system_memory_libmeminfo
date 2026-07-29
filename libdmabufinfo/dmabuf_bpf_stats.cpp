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

#include "dmabuf_bpf_stats.h"

#include <charconv>
#include <fstream>
#include <string>
#include <utility>

#include <android-base/logging.h>

namespace android {
namespace dmabufinfo {

namespace {

enum Field {inode, size, name, exporter, COUNT};

}  // anonymous namespace

bool GetDmabufBPFStats(DmabufPerBufferStats& stats) {
    constexpr const char BPF_DMABUF_ITER_PATH[] = "/sys/fs/bpf/dmabuf/prog_dmabufIter_iter_dmabuf";

    std::ifstream in(BPF_DMABUF_ITER_PATH);

    if (!in) {
        LOG(ERROR) << "Unable to access " << BPF_DMABUF_ITER_PATH;
        return false;
    }

    stats = {};

    int i = Field::inode;
    struct DmabufInfo info;
    for (std::string line; std::getline(in, line); ++i) {
        if (i % Field::COUNT == Field::inode) {
            auto [_, ec] = std::from_chars(line.data(), line.data() + line.size(), info.inode);
            if (ec != std::errc()) {
                LOG(ERROR) << "Unrecognized inode from BPF: " << line;
                return false;
            }
        } else if (i % Field::COUNT == Field::size) {
            auto [_, ec] = std::from_chars(line.data(), line.data() + line.size(), info.size);
            if (ec != std::errc()) {
                LOG(ERROR) << "Unrecognized size from BPF (ino: " << info.inode << "): " << line;
                return false;
            }
        } else if (i % Field::COUNT == Field::name) {
            // skip, currently unused
        } else if (i % Field::COUNT == Field::exporter) {
            // While buffer names are optional, exporter names are required. An empty exporter
            // here is a kernel bug. We use them as a map key below.
            if (line.empty()) {
                LOG(ERROR) << "Exporter is empty from BPF (ino: " << info.inode << ")";
                return false;
            }

            info.exp_name = line;

            auto& e = stats.exporter_info_[info.exp_name];
            e.size += info.size;
            ++e.buffer_count;

            stats.buffer_stats_.emplace_back(std::move(info));
            info = {};
        }
    }

    // All buffers require exporter names, and typically we have many more buffers than exporters.
    // Defer overall total summations until the end to avoid a few extra add ops in the per-buffer
    // loop above.
    for (const auto& [_, v] : stats.exporter_info_) {
        stats.total_.size += v.size;
        stats.total_.buffer_count += v.buffer_count;
    }

    return true;
}

}  // namespace dmabufinfo
}  // namespace android
