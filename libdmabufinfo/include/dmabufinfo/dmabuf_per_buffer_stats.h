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

#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace android {
namespace dmabufinfo {

/*
 * struct DmabufInfo: Represents information about a DMA-BUF.
 *
 * @inode: The unique inode number for the buffer.
 * @exp_name: Name of the exporter of the buffer.
 * @size: Size of the buffer in bytes.
 */
struct DmabufInfo {
    unsigned long inode;
    std::string exp_name;
    uint64_t size;
    // DO NOT MODIFY - GRF compatibility depends on binary stability of this struct.
};

struct DmabufTotal {
    uint64_t size;
    unsigned int buffer_count;
    // DO NOT MODIFY - GRF compatibility depends on binary stability of this struct.
};

class DmabufPerBufferStats {
  public:
    inline const std::vector<DmabufInfo>& buffer_stats() const { return buffer_stats_; }
    using ExporterName = std::string;
    inline const std::unordered_map<ExporterName, struct DmabufTotal>& exporter_info() const {
        return exporter_info_;
    }
    inline uint64_t total_size() const { return total_.size; }
    inline unsigned int total_count() const { return total_.buffer_count; }

    friend bool GetDmabufBPFStats(DmabufPerBufferStats& stats);
    friend bool GetDmabufSysfsStats(DmabufPerBufferStats& stats, const std::string& path);

  private:
    std::vector<DmabufInfo> buffer_stats_;
    std::unordered_map<ExporterName, struct DmabufTotal> exporter_info_;
    struct DmabufTotal total_;
};

/*
 * Reads and parses DMA-BUF statistics to create per-buffer and per-exporter stats.
 *
 * @stats: output argument that will be populated with information from DMA-BUF stats.
 *
 * Returns true on success.
 */
bool GetDmabufPerBufferStats(DmabufPerBufferStats& stats);

}  // namespace dmabufinfo
}  // namespace android
