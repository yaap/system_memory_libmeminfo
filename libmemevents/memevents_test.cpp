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
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <gtest/gtest.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#include <memevents/memevents.h>

using namespace ::android::base;
using namespace ::android::memevents;

namespace fs = std::filesystem;

static const std::filesystem::path memhealth_dir_path = "proc/memhealth";
static const std::filesystem::path sysrq_trigger_path = "proc/sysrq-trigger";

class MemEventsTest : public ::testing::Test {
  protected:
    MemEventListener memevent_listener;

    void TearDown() override { memevent_listener.deregisterAllEvents(); }

    static void SetUpTestSuite() {
        /**
         * `memhealth` driver needs to be loaded in order
         * for the `MemEventListener` to register to the memory files.
         */
        if (!std::filesystem::exists(memhealth_dir_path))
            GTEST_SKIP() << "Memhealth driver is not available";
    }
};

/**
 * Verify that `MemEventListener.registerEvent()` returns false when provided
 * invalid event types.
 */
TEST_F(MemEventsTest, MemEventListener_registerEvent_invalidEvents) {
    ASSERT_FALSE(memevent_listener.registerEvent(MemEvent::NR_MEM_EVENTS));
    ASSERT_FALSE(memevent_listener.registerEvent(MemEvent::ERROR));
}

/**
 * Verify that `MemEventListener.registerEvent()` will not fail when attempting
 * to listen to an already open event file.
 */
TEST_F(MemEventsTest, MemEventListener_registerEvent_alreadyOpenedEvent) {
    const MemEvent event_type = MemEvent::OOM_KILL;
    ASSERT_TRUE(memevent_listener.registerEvent(event_type));
    ASSERT_TRUE(memevent_listener.registerEvent(event_type));
}

/**
 * Verify that `MemEventListener.listen()` fails if no events are registered.
 */
TEST_F(MemEventsTest, MemEventListener_listen_invalidEpfd) {
    ASSERT_EQ(memevent_listener.listen(), MemEvent::ERROR);
}

/**
 * Verify that if we call `MemEventListener.deregisterEvent()` on the only/last
 * open event, that we close the `epfd` as well.
 */
TEST_F(MemEventsTest, MemEventListener_listen_closeLastEvent) {
    ASSERT_TRUE(memevent_listener.registerEvent(MemEvent::OOM_KILL));
    ASSERT_TRUE(memevent_listener.deregisterEvent(MemEvent::OOM_KILL));
    ASSERT_EQ(MemEvent::ERROR, memevent_listener.listen());
}

/**
 * Verify that if we call `MemEventListener.deregisterAllEvents()`
 * that we close the `epfd`.
 */
TEST_F(MemEventsTest, MemEventListener_listen_closeAllEvent) {
    ASSERT_TRUE(memevent_listener.registerEvent(MemEvent::OOM_KILL));
    memevent_listener.deregisterAllEvents();
    ASSERT_EQ(MemEvent::ERROR, memevent_listener.listen());
}

/**
 * Verify that `MemEventListener.deregisterEvent()` will return false when
 * provided an invalid event types.
 */
TEST_F(MemEventsTest, MemEventListener_deregisterEvent_invalidEvents) {
    ASSERT_FALSE(memevent_listener.deregisterEvent(MemEvent::NR_MEM_EVENTS));
    ASSERT_FALSE(memevent_listener.deregisterEvent(MemEvent::ERROR));
}

/**
 * Verify that the `MemEventListener.deregisterEvent()` will return true
 * when we deregister a non-registered, valid, event.
 *
 * Note that if we attempted to deregister, before calling `registerEvent()`,
 * then `deregisterEvent()` will fail since the listener would have an invalid
 * epfd at that time.
 */
TEST_F(MemEventsTest, MemEventListener_deregisterEvent_unregisteredEvent) {
    ASSERT_TRUE(memevent_listener.deregisterEvent(MemEvent::OOM_KILL));
}

/**
 * Verify that `MemEventListener.getOomEvents()` returns false
 * if the listener hasn't been registered to listen to OOM events.
 *
 * We first have to call `registerEvent()` to ensure we create a
 * epfd.
 */
TEST_F(MemEventsTest, MemEventListener_getOomEvents_invalidFd) {
    const MemEvent event_type = MemEvent::OOM_KILL;
    ASSERT_TRUE(memevent_listener.registerEvent(event_type));
    ASSERT_TRUE(memevent_listener.deregisterEvent(event_type));

    std::vector<OomKill> oom_events;
    ASSERT_FALSE(memevent_listener.getOomEvents(oom_events));
    ASSERT_TRUE(oom_events.empty());
}

/**
 * Verify that if a user calls `MemEventListener.listen()`, that we can
 * exit gracefully, without receiving any events, by calling
 * `MemEventListener.deregisterAllEvents()`.
 */
TEST_F(MemEventsTest, MemEventListener_exitListeningGracefully) {
    const MemEvent oom_event_type = MemEvent::OOM_KILL;
    std::mutex mtx;
    std::condition_variable cv;
    bool finishedCleanly = false;

    ASSERT_TRUE(memevent_listener.registerEvent(oom_event_type));

    std::thread t([&] {
        memevent_listener.listen();
        std::lock_guard lk(mtx);
        finishedCleanly = true;
        cv.notify_one();
    });

    memevent_listener.deregisterAllEvents();
    std::unique_lock lk(mtx);
    cv.wait_for(lk, std::chrono::seconds(10), [&] { return finishedCleanly; });
    ASSERT_TRUE(finishedCleanly) << "Failed to exit gracefully";
    t.join();
}

/**
 * Keep track of all the successful OOM triggers performed by
 * `MemEventsTest.triggerOom()`.
 */
static int total_oom_triggers = 0;
static int page_size = getpagesize();

class OutOfMemoryTest : public ::testing::Test {
  public:
    static void SetUpTestSuite() {
        /**
         * `memhealth` driver needs to be loaded in order
         * for the `MemEventListener` to register to the memory files.
         */
        if (!std::filesystem::exists(memhealth_dir_path))
            GTEST_SKIP() << "Memhealth driver is not available";

        if (!std::filesystem::exists(sysrq_trigger_path))
            GTEST_SKIP() << "sysrq-trigger is required to wake up the OOM killer";
    }

  protected:
    MemEventListener oom_listener;

    void TearDown() override { oom_listener.deregisterAllEvents(); }

    bool areOOMEventsEqual(OomKill event1, OomKill event2) {
        if (event1.pid != event2.pid) return false;
        if (event1.uid != event2.uid) return false;
        if (event1.timestamp_ms != event2.timestamp_ms) return false;
        if (event1.oom_score_adj != event2.oom_score_adj) return false;
        if (memcmp(event1.process_name, event2.process_name, kTaskCommLen) != 0) return false;

        return true;
    }

    /**
     * Helper function that will force the OOM killer to claim a [random]
     * victim. Note that there is no deterministic way to ensure what process
     * will be claimed by the OOM killer.
     *
     * We utilize [sysrq]
     * (https://www.kernel.org/doc/html/v4.10/admin-guide/sysrq.html)
     * to help us attempt to wake up the out-of-memory killer.
     *
     * @return true if we were able to trigger an OOM event, false otherwise.
     */
    bool triggerOom() {
        const MemEvent oom_event_type = MemEvent::OOM_KILL;
        const std::filesystem::path process_oom_path = "proc/self/oom_score_adj";

        if (!oom_listener.registerEvent(oom_event_type)) {
            LOG(ERROR) << "Failed registering to oom event";
            return false;
        }

        // Make sure that we don't kill the parent process
        if (!android::base::WriteStringToFile("-999", process_oom_path)) {
            LOG(ERROR) << "Failed writing oom score adj for parent process";
            return false;
        }

        int pid = fork();
        if (pid < 0) {
            LOG(ERROR) << "Failed to fork";
            return false;
        }
        if (pid == 0) {
            /*
             * We want to make sure that the OOM killer claims our child
             * process, this way we ensure we don't kill anything critical
             * (including this test).
             */
            if (!android::base::WriteStringToFile("1000", process_oom_path)) {
                LOG(ERROR) << "Failed writing oom score adj for child process";
                return false;
            }

            struct sysinfo info;
            if (sysinfo(&info) != 0) {
                LOG(ERROR) << "Failed to get sysinfo";
                return false;
            }
            size_t length = info.freeram / 2;

            // Allocate memory
            void* addr =
                    mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
            if (addr == MAP_FAILED) {
                LOG(ERROR) << "Failed creating mmap";
                return false;
            }

            // Fault pages
            srand(67);
            for (int i = 0; i < length; i += page_size) memset((char*)addr + i, (char)rand(), 1);

            // Use sysrq-trigger to attempt waking up the OOM killer
            if (!android::base::WriteStringToFile("f", sysrq_trigger_path)) {
                LOG(ERROR) << "Failed calling sysrq to trigger OOM killer";
                return false;
            }
            sleep(10);  // Give some time in for sysrq to wake up the OOM killer
        } else {
            wait(NULL);  // Wait until child is done
            MemEvent event_received = oom_listener.listen();
            if (event_received != oom_event_type) {
                LOG(ERROR) << "Didn't receive an OOM event";
                return false;
            }
        }
        total_oom_triggers++;
        return true;
    }
};

// Tests that depend on `triggerOom()` to succeed
/**
 * Verify that the `MemEventListener.getOomEvents()` only returns new
 * OOM events after an initial call has already been done.
 * We expect `getOomEvents()` to only read/fetch new events.
 */
TEST_F(OutOfMemoryTest, MemEventListener_getOomEvents_noDuplicateEvents) {
    const MemEvent oom_event_type = MemEvent::OOM_KILL;

    ASSERT_TRUE(oom_listener.registerEvent(oom_event_type));

    // Flush out previous OOM events
    std::vector<OomKill> initial_oom_events;
    ASSERT_TRUE(oom_listener.getOomEvents(initial_oom_events));
    initial_oom_events.clear();

    ASSERT_TRUE(triggerOom()) << "Failed to trigger OOM killer";

    ASSERT_TRUE(oom_listener.getOomEvents(initial_oom_events));

    ASSERT_TRUE(triggerOom()) << "Failed to trigger OOM killer";

    std::vector<OomKill> newer_oom_events;
    ASSERT_TRUE(oom_listener.getOomEvents(newer_oom_events));

    for (int i = 0; i < initial_oom_events.size(); i++) {
        for (int j = 0; i < newer_oom_events.size(); i++) {
            ASSERT_FALSE(areOOMEventsEqual(initial_oom_events[i], newer_oom_events[i]))
                    << "We found a duplicated event";
        }
    }
}

/**
 * Testing the happy flow for listening to out-of-memory (OOM) events.
 *
 * We don't perform a listen here since the `triggerOom()` already does
 * that for us. In the case that we have already triggered an OOM event,
 * through `triggerOom()`, then we just verify that `getOomEvents()` returns
 * us a, non-empty, list of OOM events.
 */
TEST_F(OutOfMemoryTest, MemEventListener_oomHappyFlow) {
    const MemEvent oom_event_type = MemEvent::OOM_KILL;

    ASSERT_TRUE(oom_listener.registerEvent(oom_event_type))
            << "Failed registering OOM events as an event of interest";

    if (total_oom_triggers == 0) {
        ASSERT_TRUE(triggerOom()) << "Failed to trigger OOM killer";
    }

    std::vector<OomKill> oom_events;
    oom_listener.getOomEvents(oom_events);
    ASSERT_FALSE(oom_events.empty()) << "We expect at least 1 OOM event";
}

/**
 * Verify that when we have two MemEventListeners, listening to the same event
 * of interest (OOM), that they are both reading the same entries.
 */
TEST_F(OutOfMemoryTest, MemEventListener_oomMultipleListeners) {
    const MemEvent oom_event_type = MemEvent::OOM_KILL;

    MemEventListener listener1;
    MemEventListener listener2;
    ASSERT_TRUE(listener1.registerEvent(oom_event_type));
    ASSERT_TRUE(listener2.registerEvent(oom_event_type));

    if (total_oom_triggers == 0) {
        ASSERT_TRUE(triggerOom()) << "Failed to trigger OOM killer";
    }

    std::vector<OomKill> oom_events1;
    std::vector<OomKill> oom_events2;
    ASSERT_TRUE(listener1.getOomEvents(oom_events1));
    ASSERT_TRUE(listener2.getOomEvents(oom_events2));

    ASSERT_EQ(oom_events1.size(), oom_events2.size()) << "OOM events sizes don't match";

    for (int i = 0; i < oom_events1.size(); i++) {
        ASSERT_TRUE(areOOMEventsEqual(oom_events1[i], oom_events2[i]))
                << "OOM events didn't match at index " << i;
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ::android::base::InitLogging(argv, android::base::StderrLogger);
    return RUN_ALL_TESTS();
}
