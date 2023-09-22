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
#include <unistd.h>

#include <memevents/memevents.h>

using namespace ::android::base;
using namespace ::android::memevents;

namespace fs = std::filesystem;

class MemEventsTest : public ::testing::Test {
  protected:
    MemEventListener memevent_listener;

    void TearDown() override { memevent_listener.deregisterAllEvents(); }
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

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ::android::base::InitLogging(argv, android::base::StderrLogger);
    return RUN_ALL_TESTS();
}
