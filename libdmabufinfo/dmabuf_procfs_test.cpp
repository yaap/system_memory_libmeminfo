/* Copyright (C) 2025 The Android Open Source Project
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

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <utility>

#include <sys/mman.h>
#include <unistd.h>

#include <linux/dma-buf.h>
#include <linux/dma-heap.h>

#include <gtest/gtest.h>

#include <android-base/unique_fd.h>


class ProcfsDmabufRssApiChecker : public testing::Test {
private:
    static int dmabuf_heap_alloc(int heap_fd, size_t bytes)
    {
        struct dma_heap_allocation_data data = {
            .len = bytes,
            .fd = 0,
            .fd_flags = O_RDWR | O_CLOEXEC,
            .heap_flags = 0,
        };
        int ret = ioctl(heap_fd, DMA_HEAP_IOCTL_ALLOC, &data);
        if (ret < 0)
            return ret;
        return data.fd;
    }

    const std::string RSS_PATH = "/proc/self/dmabuf_rss";
public:
    const std::string RSS_HWM_PATH = "/proc/self/dmabuf_rss_hwm";

    std::size_t read(const std::string &path) {
        std::size_t val;
        std::ifstream in(path);

        in >> val;
        return val;
    }

    std::size_t readRss() {
        return read(RSS_PATH);
    }

    std::size_t readRssHwm() {
        return read(RSS_HWM_PATH);
    }

    bool resetRssHwm() {
        android::base::unique_fd fd{TEMP_FAILURE_RETRY(open(RSS_HWM_PATH.c_str(), O_WRONLY))};
        if (!fd.ok()) return false;

        return TEMP_FAILURE_RETRY(write(fd.get(), "0", 1)) == 1;
    }

    // Returned FDs are RAII
    android::base::unique_fd allocateDmabuf(std::size_t bytes) {
        android::base::unique_fd heap_fd{TEMP_FAILURE_RETRY(open("/dev/dma_heap/system",
                                                                 O_RDONLY))};
        if(!heap_fd.ok()) {
            std::perror("Heap open failed");
            return heap_fd;
        }

        return android::base::unique_fd{dmabuf_heap_alloc(heap_fd, bytes)};
    }
protected:
    void SetUp() override {
        if (!std::filesystem::exists(RSS_PATH))
            GTEST_SKIP() << "Kernel does not have dmabuf procfs RSS API: " << RSS_PATH
                         << " does not exist.";
    }
};

TEST_F(ProcfsDmabufRssApiChecker, ZeroRssWithNoBuffers) {
    ASSERT_EQ(readRss(), 0);
}

TEST_F(ProcfsDmabufRssApiChecker, AllocateSingleFD) {
    ASSERT_EQ(readRss(), 0);

    android::base::unique_fd dmabuf = allocateDmabuf(getpagesize());
    ASSERT_TRUE(dmabuf.ok());

    ASSERT_EQ(readRss(), getpagesize());

    dmabuf.reset();
    ASSERT_EQ(readRss(), 0);
}

TEST_F(ProcfsDmabufRssApiChecker, AllocateThenDupThenCloseFDs) {
    ASSERT_EQ(readRss(), 0);

    android::base::unique_fd dmabuf = allocateDmabuf(getpagesize());
    ASSERT_TRUE(dmabuf.ok());

    ASSERT_EQ(readRss(), getpagesize());

    android::base::unique_fd duped{dup(dmabuf.get())};
    ASSERT_TRUE(duped.ok());

    ASSERT_EQ(readRss(), getpagesize());

    dmabuf.reset();
    ASSERT_EQ(readRss(), getpagesize());

    duped.reset();
    ASSERT_EQ(readRss(), 0);
}

TEST_F(ProcfsDmabufRssApiChecker, AllocateThenCloseTwoFDs) {
    ASSERT_EQ(readRss(), 0);

    android::base::unique_fd dmabuf1 = allocateDmabuf(getpagesize());
    ASSERT_TRUE(dmabuf1.ok());

    ASSERT_EQ(readRss(), getpagesize());

    android::base::unique_fd dmabuf2 = allocateDmabuf(2*getpagesize());
    ASSERT_TRUE(dmabuf2.ok());

    ASSERT_EQ(readRss(), 3*getpagesize());

    dmabuf2.reset();
    ASSERT_EQ(readRss(), getpagesize());

    dmabuf1.reset();
    ASSERT_EQ(readRss(), 0);
}

TEST_F(ProcfsDmabufRssApiChecker, MapBufferThenCloseAndUnmap) {
    ASSERT_EQ(readRss(), 0);

    android::base::unique_fd dmabuf = allocateDmabuf(getpagesize());
    ASSERT_TRUE(dmabuf.ok());

    ASSERT_EQ(readRss(), getpagesize());

    void *vm = mmap(nullptr, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, dmabuf.get(), 0);
    ASSERT_NE(vm, MAP_FAILED);

    ASSERT_EQ(readRss(), getpagesize());

    dmabuf.reset();
    ASSERT_EQ(readRss(), getpagesize()); // The FD is gone, but the mapping still exists

    ASSERT_EQ(munmap(vm, getpagesize()), 0);

    ASSERT_EQ(readRss(), 0);
}

TEST_F(ProcfsDmabufRssApiChecker, MapBufferTwiceThenCloseAndUnmap) {
    ASSERT_EQ(readRss(), 0);

    android::base::unique_fd dmabuf = allocateDmabuf(getpagesize());
    ASSERT_TRUE(dmabuf.ok());

    ASSERT_EQ(readRss(), getpagesize());

    void *vm1 = mmap(nullptr, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, dmabuf.get(), 0);
    ASSERT_NE(vm1, MAP_FAILED);

    ASSERT_EQ(readRss(), getpagesize());

    void *vm2 = mmap(nullptr, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, dmabuf.get(), 0);
    ASSERT_NE(vm2, MAP_FAILED);

    ASSERT_EQ(readRss(), getpagesize());

    dmabuf.reset();
    ASSERT_EQ(readRss(), getpagesize());

    ASSERT_EQ(munmap(vm2, getpagesize()), 0);
    ASSERT_EQ(readRss(), getpagesize());

    ASSERT_EQ(munmap(vm1, getpagesize()), 0);
    ASSERT_EQ(readRss(), 0);
}

TEST_F(ProcfsDmabufRssApiChecker, MapTwoBuffersThenCloseAndUnmap) {
    ASSERT_EQ(readRss(), 0);

    android::base::unique_fd dmabuf1 = allocateDmabuf(getpagesize());
    ASSERT_TRUE(dmabuf1.ok());

    ASSERT_EQ(readRss(), getpagesize());

    android::base::unique_fd dmabuf2 = allocateDmabuf(2*getpagesize());
    ASSERT_TRUE(dmabuf2.ok());

    ASSERT_EQ(readRss(), 3*getpagesize());

    void *vm1 = mmap(nullptr, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, dmabuf1.get(), 0);
    ASSERT_NE(vm1, MAP_FAILED);

    ASSERT_EQ(readRss(), 3*getpagesize());

    dmabuf1.reset();
    ASSERT_EQ(readRss(), 3*getpagesize());

    void *vm2 = mmap(nullptr, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, dmabuf2.get(), 0);
    ASSERT_NE(vm2, MAP_FAILED);

    dmabuf2.reset();
    ASSERT_EQ(readRss(), 3*getpagesize());

    ASSERT_EQ(munmap(vm1, getpagesize()), 0);
    ASSERT_EQ(readRss(), 2*getpagesize());

    ASSERT_EQ(munmap(vm2, 2*getpagesize()), 0);
    ASSERT_EQ(readRss(), 0);
}

TEST_F(ProcfsDmabufRssApiChecker, PartialMap) {
    ASSERT_EQ(readRss(), 0);

    android::base::unique_fd dmabuf = allocateDmabuf(2*getpagesize());
    ASSERT_TRUE(dmabuf.ok());

    ASSERT_EQ(readRss(), 2*getpagesize());

    void *vm = mmap(nullptr, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, dmabuf.get(), 0);
    ASSERT_NE(vm, MAP_FAILED);

    ASSERT_EQ(readRss(), 2*getpagesize());

    ASSERT_EQ(munmap(vm, getpagesize()), 0);
    ASSERT_EQ(readRss(), 2*getpagesize());

    vm = mmap(nullptr, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, dmabuf.get(),
              getpagesize());
    ASSERT_NE(vm, MAP_FAILED);

    ASSERT_EQ(readRss(), 2*getpagesize());

    ASSERT_EQ(munmap(vm, getpagesize()), 0);
    ASSERT_EQ(readRss(), 2*getpagesize());

    dmabuf.reset();
    ASSERT_EQ(readRss(), 0);
}

TEST_F(ProcfsDmabufRssApiChecker, PartialUnmap) {
    ASSERT_EQ(readRss(), 0);

    android::base::unique_fd dmabuf = allocateDmabuf(2*getpagesize());
    ASSERT_TRUE(dmabuf.ok());

    ASSERT_EQ(readRss(), 2*getpagesize());

    char *vm = (char *)mmap(nullptr, 2*getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED,
                            dmabuf.get(), 0);
    ASSERT_NE(vm, MAP_FAILED);

    ASSERT_EQ(readRss(), 2*getpagesize());

    dmabuf.reset();
    ASSERT_EQ(readRss(), 2*getpagesize());

    // VMA split here
    // Continue to attribute the full size of the buffer, despite the partial mapping
    ASSERT_EQ(munmap(vm, getpagesize()), 0);
    ASSERT_EQ(readRss(), 2*getpagesize());

    ASSERT_EQ(munmap(vm+getpagesize(), getpagesize()), 0);
    ASSERT_EQ(readRss(), 0);
}

TEST_F(ProcfsDmabufRssApiChecker, MremapShrink) {
    ASSERT_EQ(readRss(), 0);

    android::base::unique_fd dmabuf = allocateDmabuf(3*getpagesize());
    ASSERT_TRUE(dmabuf.ok());

    ASSERT_EQ(readRss(), 3*getpagesize());

    void *vm = mmap(nullptr, 2*getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, dmabuf.get(), 0);
    ASSERT_NE(vm, MAP_FAILED);

    ASSERT_EQ(readRss(), 3*getpagesize());

    dmabuf.reset();
    ASSERT_EQ(readRss(), 3*getpagesize());

    vm = mremap(vm, 2*getpagesize(), getpagesize(), 0, NULL);
    ASSERT_NE(vm, MAP_FAILED);
    ASSERT_EQ(readRss(), 3*getpagesize());

    ASSERT_EQ(munmap(vm, getpagesize()), 0);
    ASSERT_EQ(readRss(), 0);
}

// This test only checks that buffers from a single source (system heap) cannot be expanded,
// but buffers with other mapping implementations may (inadvertently) fail to specify VM_DONTEXPAND
// so this test is not exhaustive.
TEST_F(ProcfsDmabufRssApiChecker, MremapExpandFails) {
    ASSERT_EQ(readRss(), 0);

    android::base::unique_fd dmabuf = allocateDmabuf(2*getpagesize());
    ASSERT_TRUE(dmabuf.ok());

    ASSERT_EQ(readRss(), 2*getpagesize());

    void *vm = mmap(nullptr, getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, dmabuf.get(), 0);
    ASSERT_NE(vm, MAP_FAILED);

    ASSERT_EQ(readRss(), 2*getpagesize());

    dmabuf.reset();
    ASSERT_EQ(readRss(), 2*getpagesize());

    void *new_vm = mremap(vm, getpagesize(), 2*getpagesize(), MREMAP_MAYMOVE, NULL);
    ASSERT_EQ(new_vm, MAP_FAILED);

    ASSERT_EQ(munmap(vm, getpagesize()), 0);
    ASSERT_EQ(readRss(), 0);
}

TEST_F(ProcfsDmabufRssApiChecker, RssHwm) {
    if (!std::filesystem::exists(RSS_HWM_PATH))
            GTEST_SKIP() << "Kernel does not have dmabuf procfs RSS HWM API: " << RSS_HWM_PATH
                         << " does not exist.";

    ASSERT_TRUE(resetRssHwm());
    ASSERT_EQ(readRssHwm(), 0);

    std::vector<android::base::unique_fd> dmabufs;
    for(unsigned int i = 0; i < 10; ++i) {
        android::base::unique_fd dmabuf = allocateDmabuf(getpagesize());
        ASSERT_TRUE(dmabuf.ok());

        dmabufs.push_back(std::move(dmabuf));
    }

    ASSERT_EQ(readRss(), 10*getpagesize());
    ASSERT_GE(readRssHwm(), 10*getpagesize());

    dmabufs.clear();

    ASSERT_EQ(readRss(), 0);
    ASSERT_GE(readRssHwm(), 10*getpagesize());
}
