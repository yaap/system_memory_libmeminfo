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

#include <gtest/gtest.h>

#include <vintf/VintfObject.h>

#include "../dmabuf_bpf_stats.h"

using android::vintf::KernelVersion;
using android::vintf::RuntimeInfo;
using android::vintf::VintfObject;

TEST(libdmabufinfo, BPFDmabufIteratorLoaded) {
    // Kernels 6.12 and older have CONFIG_DMABUF_SYSFS_STATS, and the BPF dmabuf iterator is an
    // optional performance enhancement for them.
    KernelVersion first_required_kernel = KernelVersion(6, 18, 0);
    KernelVersion kernel_version = VintfObject::GetInstance()
                                           ->getRuntimeInfo(RuntimeInfo::FetchFlag::CPU_VERSION)
                                           ->kernelVersion();
    if (kernel_version < first_required_kernel) {
        GTEST_SKIP();
    }

    android::dmabufinfo::DmabufPerBufferStats stats;
    ASSERT_TRUE(android::dmabufinfo::GetDmabufBPFStats(stats))
        << "[VSR-3.4.5-002] requires devices running kernels 6.18 or newer to have dmabuf BPF "
        << "iterator support";
}
