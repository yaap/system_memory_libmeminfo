/*
 * Copyright (C) 2023 The Android Open Source Project
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
#include <filesystem>
#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <bpf/BpfUtils.h>
#include <gtest/gtest.h>
#include <string.h>
#include <unistd.h>

#include <BpfSyscallWrappers.h>

#include <memevents/memevents.h>
#include <memevents/memevents_test.h>

using namespace ::android::base;
using namespace ::android::bpf::memevents;

using android::bpf::isAtLeastKernelVersion;

namespace fs = std::filesystem;

static const MemEventClient mem_test_client = MemEventClient::TEST_CLIENT;
static const int page_size = getpagesize();
static const bool isBpfRingBufferSupported = isAtLeastKernelVersion(5, 8, 0);
static const std::string bpfRbsPaths[MemEventClient::NR_CLIENTS] = {
        MEM_EVENTS_AMS_RB, MEM_EVENTS_LMKD_RB, MEM_EVENTS_TEST_RB};
static const std::string testBpfProgPaths[NR_MEM_EVENTS] = {MEM_EVENTS_TEST_OOM_KILL_TP,
                                                            MEM_EVENTS_TEST_DIRECT_RECLAIM_START_TP,
                                                            MEM_EVENTS_TEST_DIRECT_RECLAIM_END_TP};

/*
 * Test suite to test on devices that don't support BPF, kernel <= 5.8.
 * We allow for the listener to iniailize gracefully, but every public API will
 * return false/fail.
 */
class MemEventListenerUnsupportedKernel : public ::testing::Test {
  protected:
    MemEventListener memevent_listener = MemEventListener(mem_test_client);

    static void SetUpTestSuite() {
        if (isBpfRingBufferSupported) {
            GTEST_SKIP()
                    << "BPF ring buffers is supported on this kernel, running alternative tests";
        }
    }

    void TearDown() override { memevent_listener.deregisterAllEvents(); }
};

/*
 * Listener shouldn't fail when initializing on a kernel that doesn't support BPF.
 */
TEST_F(MemEventListenerUnsupportedKernel, initialize_invalid_client) {
    std::unique_ptr<MemEventListener> listener =
            std::make_unique<MemEventListener>(MemEventClient::AMS);
    ASSERT_TRUE(listener) << "Failed to initialize listener on older kernel";
}

/*
 * Register will fail when running on a older kernel, even when we pass a valid event type.
 */
TEST_F(MemEventListenerUnsupportedKernel, fail_to_register) {
    ASSERT_FALSE(memevent_listener.registerEvent(MEM_EVENT_OOM_KILL))
            << "Listener should fail to register valid event type on an unsupported kernel";
    ASSERT_FALSE(memevent_listener.registerEvent(NR_MEM_EVENTS))
            << "Listener should fail to register invalid event type";
}

/*
 * Listen will fail when running on a older kernel.
 * The listen() function always checks first if we are running on an older kernel,
 * therefore we don't need to register for an event before trying to call listen.
 */
TEST_F(MemEventListenerUnsupportedKernel, fail_to_listen) {
    ASSERT_FALSE(memevent_listener.listen()) << "listen() should fail on unsupported kernel";
}

/*
 * Just like the other APIs, deregister will return false immediately on an older
 * kernel.
 */
TEST_F(MemEventListenerUnsupportedKernel, fail_to_unregister_event) {
    ASSERT_FALSE(memevent_listener.deregisterEvent(MEM_EVENT_OOM_KILL))
            << "Listener should fail to deregister valid event type on an older kernel";
    ASSERT_FALSE(memevent_listener.deregisterEvent(NR_MEM_EVENTS))
            << "Listener should fail to deregister invalid event type, regardless of kernel "
               "version";
}

/*
 * The `getMemEvents()` API should fail on an older kernel.
 */
TEST_F(MemEventListenerUnsupportedKernel, fail_to_get_mem_events) {
    std::vector<mem_event_t> mem_events;
    ASSERT_FALSE(memevent_listener.getMemEvents(mem_events))
            << "Fetching memory events should fail on an older kernel";
}

/*
 * Test suite verifies that all the BPF programs and ring buffers are loaded.
 */
class MemEventsBpfSetupTest : public ::testing::Test {
  protected:
    static void SetUpTestSuite() {
        if (!isBpfRingBufferSupported) {
            GTEST_SKIP() << "BPF ring buffers not supported in kernels below 5.8";
        }
    }
};

/*
 * Verify that all the ams bpf-programs are loaded.
 */
TEST_F(MemEventsBpfSetupTest, loaded_ams_progs) {
    ASSERT_TRUE(std::filesystem::exists(MEM_EVENTS_AMS_OOM_MARK_VICTIM_TP))
            << "Failed to find ams mark_victim bpf-program";
}

/*
 * Verify that all the lmkd bpf-programs are loaded.
 */
TEST_F(MemEventsBpfSetupTest, loaded_lmkd_progs) {
    ASSERT_TRUE(std::filesystem::exists(MEM_EVENTS_LMKD_VMSCAN_DR_BEGIN_TP))
            << "Failed to find lmkd direct_reclaim_begin bpf-program";
    ASSERT_TRUE(std::filesystem::exists(MEM_EVENTS_LMKD_VMSCAN_DR_END_TP))
            << "Failed to find lmkd direct_reclaim_end bpf-program";
}

/*
 * Verify that all the memevents test bpf-programs are loaded.
 */
TEST_F(MemEventsBpfSetupTest, loaded_test_progs) {
    for (int i = 0; i < NR_MEM_EVENTS; i++) {
        ASSERT_TRUE(std::filesystem::exists(testBpfProgPaths[i]))
                << "Failed to find testing bpf-prog: " << testBpfProgPaths[i];
    }
}

/*
 * Verify that all [bpf] ring buffer's are loaded.
 * We expect to have at least 1 ring buffer for each client in `MemEventClient`.
 */
TEST_F(MemEventsBpfSetupTest, loaded_ring_buffers) {
    for (int i = 0; i < MemEventClient::NR_CLIENTS; i++) {
        ASSERT_TRUE(std::filesystem::exists(bpfRbsPaths[i]))
                << "Failed to find bpf ring-buffer: " << bpfRbsPaths[i];
    }
}

class MemEventsListenerTest : public ::testing::Test {
  protected:
    MemEventListener memevent_listener = MemEventListener(mem_test_client);

    static void SetUpTestSuite() {
        if (!isBpfRingBufferSupported) {
            GTEST_SKIP() << "BPF ring buffers not supported in kernels below 5.8";
        }
    }

    void TearDown() override { memevent_listener.deregisterAllEvents(); }
};

/*
 * MemEventListener should fail, through a `std::abort()`, when attempted to initialize
 * with an invalid `MemEventClient`. By passing `MemEventClient::NR_CLIENTS`, and attempting
 * to convert/pass `-1` as a client, we expect the listener initialization to fail.
 */
TEST_F(MemEventsListenerTest, initialize_invalid_client) {
    EXPECT_DEATH(MemEventListener listener(MemEventClient::NR_CLIENTS), "");
    EXPECT_DEATH(MemEventListener listener(static_cast<MemEventClient>(-1)), "");
}

/*
 * MemEventListener should NOT fail when initializing for all valid `MemEventClient`.
 * We considered a `MemEventClient` valid if its between 0 and MemEventClient::NR_CLIENTS.
 */
TEST_F(MemEventsListenerTest, initialize_valid_clients) {
    std::unique_ptr<MemEventListener> listener;
    for (int i = 0; i < MemEventClient::NR_CLIENTS; i++) {
        const MemEventClient client = static_cast<MemEventClient>(i);
        listener = std::make_unique<MemEventListener>(client);
        ASSERT_TRUE(listener) << "MemEventListener failed to initialize with valid client value: "
                              << client;
    }
}

/*
 * MemEventClient base client should equal to AMS client.
 */
TEST_F(MemEventsListenerTest, base_client_equal_ams_client) {
    ASSERT_EQ(static_cast<int>(MemEventClient::BASE), static_cast<int>(MemEventClient::AMS))
            << "Base client should be equal to AMS client";
}

/*
 * Validate `registerEvent()` fails with values >= `NR_MEM_EVENTS`.
 */
TEST_F(MemEventsListenerTest, register_event_invalid_values) {
    ASSERT_FALSE(memevent_listener.registerEvent(NR_MEM_EVENTS));
    ASSERT_FALSE(memevent_listener.registerEvent(NR_MEM_EVENTS + 1));
    ASSERT_FALSE(memevent_listener.registerEvent(-1));
}

/*
 * Validate that `registerEvent()` always returns true when we try registering
 * the same [valid] event/value.
 */
TEST_F(MemEventsListenerTest, register_event_repeated_event) {
    const int event_type = MEM_EVENT_OOM_KILL;
    ASSERT_TRUE(memevent_listener.registerEvent(event_type));
    ASSERT_TRUE(memevent_listener.registerEvent(event_type));
    ASSERT_TRUE(memevent_listener.registerEvent(event_type));
}

/*
 * Validate that `registerEvent()` is able to register all the `MEM_EVENT_*` values
 * from `bpf_types.h`.
 */
TEST_F(MemEventsListenerTest, register_event_valid_values) {
    for (unsigned int i = 0; i < NR_MEM_EVENTS; i++)
        ASSERT_TRUE(memevent_listener.registerEvent(i)) << "Failed to register event: " << i;
}

/*
 * `listen()` should return false when no events have been registered.
 */
TEST_F(MemEventsListenerTest, listen_no_registered_events) {
    ASSERT_FALSE(memevent_listener.listen());
}

/*
 * Validate `deregisterEvent()` fails with values >= `NR_MEM_EVENTS`.
 * Exactly like `register_event_invalid_values` test.
 */
TEST_F(MemEventsListenerTest, deregister_event_invalid_values) {
    ASSERT_FALSE(memevent_listener.deregisterEvent(NR_MEM_EVENTS));
    ASSERT_FALSE(memevent_listener.deregisterEvent(NR_MEM_EVENTS + 1));
    ASSERT_FALSE(memevent_listener.deregisterEvent(-1));
}

/*
 * Validate that `deregisterEvent()` always returns true when we try
 * deregistering the same [valid] event/value.
 */
TEST_F(MemEventsListenerTest, deregister_repeated_event) {
    const int event_type = MEM_EVENT_DIRECT_RECLAIM_BEGIN;
    ASSERT_TRUE(memevent_listener.registerEvent(event_type));
    ASSERT_TRUE(memevent_listener.deregisterEvent(event_type));
    ASSERT_TRUE(memevent_listener.deregisterEvent(event_type));
}

/*
 * Verify that the `deregisterEvent()` will return true
 * when we deregister a non-registered, valid, event.
 */
TEST_F(MemEventsListenerTest, deregister_unregistered_event) {
    ASSERT_TRUE(memevent_listener.deregisterEvent(MEM_EVENT_DIRECT_RECLAIM_END));
}

/*
 * Validate that the `deregisterAllEvents()` closes all the registered
 * events.
 */
TEST_F(MemEventsListenerTest, deregister_all_events) {
    ASSERT_TRUE(memevent_listener.registerEvent(MEM_EVENT_OOM_KILL));
    ASSERT_TRUE(memevent_listener.registerEvent(MEM_EVENT_DIRECT_RECLAIM_BEGIN));
    memevent_listener.deregisterAllEvents();
    ASSERT_FALSE(memevent_listener.listen())
            << "Expected to fail since we are not registered to any events";
}

/*
 * Validating that `MEM_EVENT_BASE` is equal to `MEM_EVENT_OOM_KILL`.
 */
TEST_F(MemEventsListenerTest, base_and_oom_events_are_equal) {
    ASSERT_EQ(MEM_EVENT_OOM_KILL, MEM_EVENT_BASE)
            << "MEM_EVENT_BASE should be equal to MEM_EVENT_OOM_KILL";
}

class MemEventsListenerBpf : public ::testing::Test {
  private:
    android::base::unique_fd mProgram;

    void setUpProgram(unsigned int event_type) {
        ASSERT_TRUE(event_type < NR_MEM_EVENTS) << "Invalid event type provided";

        int bpf_fd = android::bpf::retrieveProgram(testBpfProgPaths[event_type].c_str());
        ASSERT_NE(bpf_fd, -1) << "Retrieve bpf program failed with prog path: "
                              << testBpfProgPaths[event_type];
        mProgram.reset(bpf_fd);

        ASSERT_GE(mProgram.get(), 0)
                << testBpfProgPaths[event_type] << " was either not found or inaccessible.";
    }

    /*
     * Always call this after `setUpProgram()`, in order to make sure that the
     * correct `mProgram` was set.
     */
    void RunProgram(unsigned int event_type) {
        errno = 0;
        switch (event_type) {
            case MEM_EVENT_OOM_KILL:
                struct mark_victim_args mark_victim_fake_args;
                android::bpf::runProgram(mProgram, &mark_victim_fake_args,
                                         sizeof(mark_victim_fake_args));
                break;
            case MEM_EVENT_DIRECT_RECLAIM_BEGIN:
                struct direct_reclaim_begin_args dr_begin_fake_args;
                android::bpf::runProgram(mProgram, &dr_begin_fake_args, sizeof(dr_begin_fake_args));
                break;
            case MEM_EVENT_DIRECT_RECLAIM_END:
                struct direct_reclaim_end_args dr_end_fake_args;
                android::bpf::runProgram(mProgram, &dr_end_fake_args, sizeof(dr_end_fake_args));
                break;
            default:
                FAIL() << "Invalid event type provided";
        }
        EXPECT_EQ(errno, 0);
    }

  protected:
    MemEventListener mem_listener = MemEventListener(mem_test_client);

    static void SetUpTestSuite() {
        if (!isAtLeastKernelVersion(5, 8, 0)) {
            GTEST_SKIP() << "BPF ring buffers not supported below 5.8";
        }
    }

    /*
     * Helper function to insert mocked data into the testing [bpf] ring buffer.
     * This will trigger the `listen()` if its registered to the given `event_type`.
     */
    void setMockDataInRb(mem_event_type_t event_type) {
        setUpProgram(event_type);
        RunProgram(event_type);
    }

    /*
     * Test that the `listen()` returns true.
     * We setup some mocked event data into the testing [bpf] ring-buffer, to make
     * sure the `listen()` is triggered.
     */
    void testListenEvent(unsigned int event_type) {
        ASSERT_TRUE(event_type < NR_MEM_EVENTS) << "Invalid event type provided";

        setMockDataInRb(event_type);

        ASSERT_TRUE(mem_listener.listen(5000));  // 5 second timeout
    }
};

/*
 * Validate that `listen()` is triggered when we the bpf-rb receives
 * a OOM event.
 */
TEST_F(MemEventsListenerBpf, listener_bpf_oom_kill) {
    const mem_event_type_t event_type = MEM_EVENT_OOM_KILL;

    ASSERT_TRUE(mem_listener.registerEvent(event_type));
    testListenEvent(event_type);

    std::vector<mem_event_t> mem_events;
    ASSERT_TRUE(mem_listener.getMemEvents(mem_events)) << "Failed fetching events";
    ASSERT_FALSE(mem_events.empty()) << "Expected for mem_events to have at least 1 mocked event";
    ASSERT_EQ(mem_events[0].type, event_type) << "Didn't receive a OOM event";

    /*
     * This values are set inside the testing prog `memevents_test.h`. These values can't be passed
     * from the test to the bpf-prog.
     */
    ASSERT_EQ(mem_events[0].event_data.oom_kill.pid, mocked_oom_event.event_data.oom_kill.pid)
            << "Didn't receive expected PID";
    ASSERT_EQ(mem_events[0].event_data.oom_kill.uid, mocked_oom_event.event_data.oom_kill.uid)
            << "Didn't receive expected UID";
    ASSERT_EQ(mem_events[0].event_data.oom_kill.oom_score_adj,
              mocked_oom_event.event_data.oom_kill.oom_score_adj)
            << "Didn't receive expected OOM score";
    ASSERT_EQ(strcmp(mem_events[0].event_data.oom_kill.process_name,
                     mocked_oom_event.event_data.oom_kill.process_name),
              0)
            << "Didn't receive expected process name";
}

/*
 * Validate that `listen()` is triggered when we the bpf-rb receives
 * a direct reclain start event.
 */
TEST_F(MemEventsListenerBpf, listener_bpf_direct_reclaim_begin) {
    const mem_event_type_t event_type = MEM_EVENT_DIRECT_RECLAIM_BEGIN;

    ASSERT_TRUE(mem_listener.registerEvent(event_type));
    testListenEvent(event_type);

    std::vector<mem_event_t> mem_events;
    ASSERT_TRUE(mem_listener.getMemEvents(mem_events)) << "Failed fetching events";
    ASSERT_FALSE(mem_events.empty()) << "Expected for mem_events to have at least 1 mocked event";
    ASSERT_EQ(mem_events[0].type, event_type) << "Didn't receive a direct reclaim begin event";
}

/*
 * Validate that `listen()` is triggered when we the bpf-rb receives
 * a direct reclain end event.
 */
TEST_F(MemEventsListenerBpf, listener_bpf_direct_reclaim_end) {
    const mem_event_type_t event_type = MEM_EVENT_DIRECT_RECLAIM_END;

    ASSERT_TRUE(mem_listener.registerEvent(event_type));
    testListenEvent(event_type);

    std::vector<mem_event_t> mem_events;
    ASSERT_TRUE(mem_listener.getMemEvents(mem_events)) << "Failed fetching events";
    ASSERT_FALSE(mem_events.empty()) << "Expected for mem_events to have at least 1 mocked event";
    ASSERT_EQ(mem_events[0].type, event_type) << "Didn't receive a direct reclaim end event";
}

/*
 * `listen()` should timeout, and return false, when a memory event that
 * we are not registered for is triggered.
 */
TEST_F(MemEventsListenerBpf, no_register_events_listen_fails) {
    const mem_event_type_t event_type = MEM_EVENT_DIRECT_RECLAIM_END;
    setMockDataInRb(event_type);
    ASSERT_FALSE(mem_listener.listen(5000));  // 5 second timeout
}

/*
 * `getMemEvents()` should return an empty list, when a memory event that
 * we are not registered for, is triggered.
 */
TEST_F(MemEventsListenerBpf, getMemEvents_no_register_events) {
    const mem_event_type_t event_type = MEM_EVENT_OOM_KILL;
    setMockDataInRb(event_type);

    std::vector<mem_event_t> mem_events;
    ASSERT_TRUE(mem_listener.getMemEvents(mem_events)) << "Failed fetching events";
    ASSERT_TRUE(mem_events.empty());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ::android::base::InitLogging(argv, android::base::StderrLogger);
    return RUN_ALL_TESTS();
}
