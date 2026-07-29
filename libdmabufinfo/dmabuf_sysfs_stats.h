/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <string>

#include <dmabufinfo/dmabuf_per_buffer_stats.h>

namespace android {
namespace dmabufinfo {

/*
 * Reads and parses DMA-BUF statistics from sysfs to create per-buffer
 * and per-exporter stats.
 *
 * @stats: output argument that will be populated with information from DMA-BUF sysfs stats.
 * @path: Not for use by clients, to be used only for unit testing.
 *
 * Returns true on success.
 */
bool GetDmabufSysfsStats(DmabufPerBufferStats& stats,
                         const std::string& path = "/sys/kernel/dmabuf/buffers");

}  // namespace dmabufinfo
}  // namespace android
