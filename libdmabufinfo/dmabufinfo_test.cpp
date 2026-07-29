/* Copyright (C) 2019 The Android Open Source Project
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
#include <inttypes.h>
#include <linux/dma-buf.h>
#include <poll.h>
#include <string.h>
#include <sys/types.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <unistd.h>

#include "dmabuf_bpf_stats.h"
#include "dmabuf_sysfs_stats.h"
#include <dmabufinfo/dmabufinfo.h>

using namespace ::android::dmabufinfo;
using namespace ::android::base;

namespace fs = std::filesystem;

class fd_sharer {
  public:
    fd_sharer();
    ~fd_sharer() { kill(); }

    bool ok() const { return child_pid > 0; }
    bool sendfd(int fd);
    bool kill();
    pid_t pid() const { return child_pid; }

  private:
    unique_fd parent_fd, child_fd;
    pid_t child_pid;

    void run();
};

fd_sharer::fd_sharer() : parent_fd{}, child_fd{}, child_pid{-1} {
    bool sp_ok = android::base::Socketpair(SOCK_STREAM, &parent_fd, &child_fd);
    if (!sp_ok) return;

    child_pid = fork();
    if (child_pid < 0) return;

    if (child_pid == 0) run();
}

bool fd_sharer::kill() {
    int err = ::kill(child_pid, SIGKILL);
    if (err < 0) return false;

    return ::waitpid(child_pid, nullptr, 0) == child_pid;
}

void fd_sharer::run() {
    while (true) {
        int fd;
        char unused = 0;

        iovec iov{};
        iov.iov_base = &unused;
        iov.iov_len = sizeof(unused);

        msghdr msg{};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        char cmsg_buf[CMSG_SPACE(sizeof(fd))];
        msg.msg_control = cmsg_buf;
        msg.msg_controllen = sizeof(cmsg_buf);

        cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(fd));

        ssize_t s = TEMP_FAILURE_RETRY(recvmsg(child_fd, &msg, 0));
        if (s == -1) break;

        s = TEMP_FAILURE_RETRY(write(child_fd, &unused, sizeof(unused)));
        if (s == -1) break;
    }
}

bool fd_sharer::sendfd(int fd) {
    char unused = 0;

    iovec iov{};
    iov.iov_base = &unused;
    iov.iov_len = sizeof(unused);

    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    char cmsg_buf[CMSG_SPACE(sizeof(fd))];
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);

    cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fd));

    int* fd_buf = reinterpret_cast<int*>(CMSG_DATA(cmsg));
    *fd_buf = fd;

    ssize_t s = TEMP_FAILURE_RETRY(sendmsg(parent_fd, &msg, 0));
    if (s == -1) return false;

    // The target process installs the fd into its fd table during recvmsg().
    // So if we return now, there's a brief window between sendfd() finishing
    // and libmemoryinfo actually seeing that the buffer has been shared.  This
    // window is just large enough to break tests.
    //
    // To work around this, wait for the target process to respond with a dummy
    // byte, with a timeout of 1 s.
    pollfd p{};
    p.fd = parent_fd;
    p.events = POLL_IN;
    int ready = poll(&p, 1, 1000);
    if (ready != 1) return false;

    s = TEMP_FAILURE_RETRY(read(parent_fd, &unused, sizeof(unused)));
    if (s == -1) return false;

    return true;
}

#define EXPECT_ONE_BUF_EQ(_bufptr, _name, _fdrefs, _maprefs, _expname, _count, _size) \
    do {                                                                              \
        EXPECT_EQ(_bufptr->name(), _name);                                            \
        EXPECT_EQ(_bufptr->fdrefs().size(), _fdrefs);                                 \
        EXPECT_EQ(_bufptr->maprefs().size(), _maprefs);                               \
        EXPECT_EQ(_bufptr->exporter(), _expname);                                     \
        EXPECT_EQ(_bufptr->count(), _count);                                          \
        EXPECT_EQ(_bufptr->size(), _size);                                            \
    } while (0)

#define EXPECT_PID_IN_FDREFS(_bufptr, _pid, _expect)                         \
    do {                                                                     \
        const std::unordered_map<pid_t, int>& _fdrefs = _bufptr->fdrefs();   \
        auto _ref = _fdrefs.find(_pid);                                      \
        EXPECT_EQ((_ref != _fdrefs.end()), _expect);                         \
    } while (0)

#define EXPECT_PID_IN_MAPREFS(_bufptr, _pid, _expect)                        \
    do {                                                                     \
        const std::unordered_map<pid_t, int>& _maprefs = _bufptr->maprefs(); \
        auto _ref = _maprefs.find(_pid);                                     \
        EXPECT_EQ((_ref != _maprefs.end()), _expect);                        \
    } while (0)

class DmaBufSysfsStatsParser : public ::testing::Test {
  public:
    virtual void SetUp() {
        fs::current_path(fs::temp_directory_path());
        buffer_stats_path = fs::current_path() / "buffers";
        ASSERT_TRUE(fs::create_directory(buffer_stats_path));
    }
    virtual void TearDown() { fs::remove_all(buffer_stats_path); }

    std::filesystem::path buffer_stats_path;
};

TEST_F(DmaBufSysfsStatsParser, TestReadDmaBufSysfsStats) {
    using android::base::StringPrintf;

    for (unsigned int inode_number = 74831; inode_number < 74841; inode_number++) {
        auto buffer_path = buffer_stats_path / StringPrintf("%u", inode_number);
        ASSERT_TRUE(fs::create_directories(buffer_path));

        auto buffer_size_path = buffer_path / "size";
        const std::string buffer_size = "4096";
        ASSERT_TRUE(android::base::WriteStringToFile(buffer_size, buffer_size_path));

        auto exp_name_path = buffer_path / "exporter_name";
        const std::string exp_name = "system";
        ASSERT_TRUE(android::base::WriteStringToFile(exp_name, exp_name_path));
    }

    DmabufPerBufferStats stats;
    ASSERT_TRUE(GetDmabufSysfsStats(stats, buffer_stats_path.c_str()));

    auto buffer_stats = stats.buffer_stats();
    ASSERT_EQ(buffer_stats.size(), 10UL);

    auto buf_info = buffer_stats[0];
    EXPECT_EQ(buf_info.inode, 74831UL);
    EXPECT_EQ(buf_info.exp_name, "system");
    EXPECT_EQ(buf_info.size, 4096UL);

    auto exporter_stats = stats.exporter_info();
    ASSERT_EQ(exporter_stats.size(), 1UL);
    auto exp_info = exporter_stats.find("system");
    ASSERT_TRUE(exp_info != exporter_stats.end());
    EXPECT_EQ(exp_info->second.size, 40960UL);
    EXPECT_EQ(exp_info->second.buffer_count, 10UL);

    auto total_size = stats.total_size();
    EXPECT_EQ(total_size, 40960UL);

    auto total_count = stats.total_count();
    EXPECT_EQ(total_count, 10UL);
}

class DmaBufProcessStatsTest : public ::testing::Test {
  public:
    virtual void SetUp() {
        fs::current_path(fs::temp_directory_path());
        dmabuf_sysfs_path = fs::current_path() / "buffers";
        procfs_path = fs::current_path() / "proc";
        ASSERT_TRUE(fs::create_directory(dmabuf_sysfs_path));
        ASSERT_TRUE(fs::create_directory(procfs_path));
        pid_path = procfs_path / android::base::StringPrintf("%d", pid);
        ASSERT_TRUE(fs::create_directories(pid_path));
        pid_fdinfo_path = pid_path / "fdinfo";
        ASSERT_TRUE(fs::create_directories(pid_fdinfo_path));
    }
    virtual void TearDown() {
        fs::remove_all(dmabuf_sysfs_path);
        fs::remove_all(procfs_path);
    }

    void AddFdInfo(unsigned int inode, unsigned int size, bool is_dmabuf) {
        std::string dmabuf_fdinfo = android::base::StringPrintf(
                "size:\t%u\ncount:\t1\nexp_name:\t%s\n", size, exporter.c_str());
        std::string fdinfo =
                android::base::StringPrintf("pos:\t21\nflags:\t0032\nmnt_id:\t02\nino:\t%u\n%s",
                                            inode, (is_dmabuf) ? dmabuf_fdinfo.c_str() : "");

        auto fdinfo_file_path = pid_fdinfo_path / android::base::StringPrintf("%d", fd++);
        ASSERT_TRUE(android::base::WriteStringToFile(fdinfo, fdinfo_file_path));
    }

    void AddSysfsDmaBufStats(unsigned int inode, unsigned int size) {
        auto buffer_path = dmabuf_sysfs_path / android::base::StringPrintf("%u", inode);
        ASSERT_TRUE(fs::create_directory(buffer_path));

        auto size_path = buffer_path / "size";
        ASSERT_TRUE(android::base::WriteStringToFile(android::base::StringPrintf("%u", size),
                                                     size_path));

        auto exporter_path = buffer_path / "exporter_name";
        ASSERT_TRUE(android::base::WriteStringToFile(exporter, exporter_path));
    }

    std::string CreateMapEntry(unsigned int inode, unsigned int size, bool is_dmabuf) {
        return android::base::StringPrintf("0000000000-%010x rw-s 00000000 00:08 %u %s", size,
                                           inode, (is_dmabuf) ? "/dmabuf:" : "/not/dmabuf/");
    }

    void AddMapEntries(std::vector<std::string> entries) {
        std::string maps_content = android::base::Join(entries, '\n');

        auto maps_file_path = pid_path / "maps";
        ASSERT_TRUE(android::base::WriteStringToFile(maps_content, maps_file_path));
    }

    std::filesystem::path dmabuf_sysfs_path;
    std::filesystem::path procfs_path;
    std::filesystem::path pid_path;
    std::filesystem::path pid_fdinfo_path;
    std::string exporter = "system_heap";
    int pid = 10;
    int fd = 0;
};

TEST_F(DmaBufProcessStatsTest, TestReadDmaBufInfo) {
    AddFdInfo(1, 1024, false);
    AddFdInfo(2, 2048, true);  // Dmabuf 1

    std::vector<std::string> map_entries;
    map_entries.emplace_back(CreateMapEntry(3, 1024, false));
    map_entries.emplace_back(CreateMapEntry(4, 1024, true));  // Dmabuf 2
    AddMapEntries(map_entries);

    AddSysfsDmaBufStats(2, 2048);  // Dmabuf 1
    AddSysfsDmaBufStats(4, 1024);  // Dmabuf 2

    android::dmabufinfo::DmabufPerBufferStats stats;
    ASSERT_TRUE(GetDmabufSysfsStats(stats, dmabuf_sysfs_path));

    std::vector<DmaBuffer> dmabufs;
    ASSERT_TRUE(ReadDmaBufInfo(pid, dmabufs, stats, true, procfs_path));

    ASSERT_EQ(dmabufs.size(), 2u);

    auto dmabuf1 = std::find_if(dmabufs.begin(), dmabufs.end(),
                                [](const DmaBuffer& dmabuf) { return dmabuf.inode() == 2; });
    ASSERT_NE(dmabuf1, dmabufs.end());
    ASSERT_EQ(dmabuf1->size(), 2048u);
    ASSERT_EQ(dmabuf1->fdrefs().size(), 1u);
    ASSERT_EQ(dmabuf1->maprefs().size(), 0u);
    ASSERT_EQ(dmabuf1->total_refs(), 1u);
    ASSERT_EQ(dmabuf1->exporter(), exporter);

    auto dmabuf2 = std::find_if(dmabufs.begin(), dmabufs.end(),
                                [](const DmaBuffer& dmabuf) { return dmabuf.inode() == 4; });
    ASSERT_NE(dmabuf2, dmabufs.end());
    ASSERT_EQ(dmabuf2->size(), 1024u);
    ASSERT_EQ(dmabuf2->fdrefs().size(), 0u);
    ASSERT_EQ(dmabuf2->maprefs().size(), 1u);
    ASSERT_EQ(dmabuf2->total_refs(), 1u);
    ASSERT_EQ(dmabuf2->exporter(), exporter);
}

TEST_F(DmaBufProcessStatsTest, TestReadDmaBufFdRefs) {
    AddFdInfo(1, 1024, false);
    AddFdInfo(2, 2048, true);  // Dmabuf 1
    AddFdInfo(2, 2048, true);  // Dmabuf 1
    AddFdInfo(3, 1024, true);  // Dmabuf 2

    std::vector<DmaBuffer> dmabufs;
    ASSERT_TRUE(ReadDmaBufFdRefs(pid, dmabufs, procfs_path));
    ASSERT_EQ(dmabufs.size(), 2u);

    const auto& dmabuf1 = std::find_if(dmabufs.begin(), dmabufs.end(),
                                       [](const DmaBuffer& dmabuf) { return dmabuf.inode() == 2; });

    ASSERT_EQ(dmabuf1->size(), 2048u);
    ASSERT_EQ(dmabuf1->fdrefs().size(), 1u);  // Only one process has FDs to this buffer
    ASSERT_EQ(dmabuf1->maprefs().size(), 0u);
    ASSERT_EQ(dmabuf1->total_refs(), 2u);
    ASSERT_EQ(dmabuf1->exporter(), exporter);

    // Verify process has 2 FDs to this buffer
    ASSERT_NE(dmabuf1, dmabufs.end());
    const auto& fdrefs1 = dmabuf1->fdrefs();
    const auto& pid_fdrefs1 = fdrefs1.find(pid);
    ASSERT_NE(pid_fdrefs1, fdrefs1.end());
    ASSERT_EQ(pid_fdrefs1->second, 2);

    const auto& dmabuf2 = std::find_if(dmabufs.begin(), dmabufs.end(),
                                       [](const DmaBuffer& dmabuf) { return dmabuf.inode() == 3; });
    ASSERT_EQ(dmabuf2->size(), 1024u);
    ASSERT_EQ(dmabuf2->fdrefs().size(), 1u);  // Only one process has FDs to this buffer
    ASSERT_EQ(dmabuf2->maprefs().size(), 0u);
    ASSERT_EQ(dmabuf2->total_refs(), 1u);
    ASSERT_EQ(dmabuf2->exporter(), exporter);

    // Verify process only has 1 FD to this buffer
    ASSERT_NE(dmabuf2, dmabufs.end());
    const auto& fdrefs2 = dmabuf2->fdrefs();
    const auto& pid_fdrefs2 = fdrefs2.find(pid);
    ASSERT_NE(pid_fdrefs2, fdrefs2.end());
    ASSERT_EQ(pid_fdrefs2->second, 1);
}

TEST_F(DmaBufProcessStatsTest, TestReadDmaBufMapRefs) {
    std::vector<std::string> map_entries;
    map_entries.emplace_back(CreateMapEntry(1, 1024, false));
    map_entries.emplace_back(CreateMapEntry(2, 1024, true));  // Dmabuf 1
    map_entries.emplace_back(CreateMapEntry(2, 1024, true));  // Dmabuf 1
    map_entries.emplace_back(CreateMapEntry(3, 2048, true));  // Dmabuf 2
    AddMapEntries(map_entries);

    AddSysfsDmaBufStats(2, 1024);  // Dmabuf 1
    AddSysfsDmaBufStats(3, 2048);  // Dmabuf 2

    android::dmabufinfo::DmabufPerBufferStats stats;
    ASSERT_TRUE(GetDmabufSysfsStats(stats, dmabuf_sysfs_path));

    std::vector<DmaBuffer> dmabufs;
    ASSERT_TRUE(ReadDmaBufMapRefs(pid, dmabufs, stats, procfs_path));
    ASSERT_EQ(dmabufs.size(), 2u);

    const auto& dmabuf1 = std::find_if(dmabufs.begin(), dmabufs.end(),
                                       [](const DmaBuffer& dmabuf) { return dmabuf.inode() == 2; });

    ASSERT_EQ(dmabuf1->size(), 1024u);
    ASSERT_EQ(dmabuf1->fdrefs().size(), 0u);
    ASSERT_EQ(dmabuf1->maprefs().size(), 1u);  // Only one process mapped this buffer
    ASSERT_EQ(dmabuf1->total_refs(), 2u);
    ASSERT_EQ(dmabuf1->exporter(), exporter);

    // Verify process mapped this buffer twice
    ASSERT_NE(dmabuf1, dmabufs.end());
    const auto& maprefs1 = dmabuf1->maprefs();
    const auto& pid_maprefs1 = maprefs1.find(pid);
    ASSERT_NE(pid_maprefs1, maprefs1.end());
    ASSERT_EQ(pid_maprefs1->second, 2);

    const auto& dmabuf2 = std::find_if(dmabufs.begin(), dmabufs.end(),
                                       [](const DmaBuffer& dmabuf) { return dmabuf.inode() == 3; });
    ASSERT_EQ(dmabuf2->size(), 2048u);
    ASSERT_EQ(dmabuf2->fdrefs().size(), 0u);
    ASSERT_EQ(dmabuf2->maprefs().size(), 1u);  // Only one process mapped this buffer
    ASSERT_EQ(dmabuf2->total_refs(), 1u);
    ASSERT_EQ(dmabuf2->exporter(), exporter);

    // Verify process mapped this buffer only once
    ASSERT_NE(dmabuf2, dmabufs.end());
    const auto& maprefs2 = dmabuf2->maprefs();
    const auto& pid_maprefs2 = maprefs2.find(pid);
    ASSERT_NE(pid_maprefs2, maprefs2.end());
    ASSERT_EQ(pid_maprefs2->second, 1);
}

TEST(DmaBufBPF, IteratorLoaded) {
    android::dmabufinfo::DmabufPerBufferStats stats;
    ASSERT_TRUE(android::dmabufinfo::GetDmabufBPFStats(stats));
}
