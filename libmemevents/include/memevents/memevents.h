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

#pragma once

#include <cstddef>
#include <deque>
#include <vector>

namespace android {
namespace memevents {

static const int kTaskCommLen = 16;  // linux/sched.h

enum MemEvent {
    OOM_KILL = 0,
    // NR_MEM_EVENTS should always come after the last valid event type
    NR_MEM_EVENTS,
    ERROR = -1,
};

struct OomKill {
    int pid;
    long uid;
    unsigned long long timestamp_ms;
    short oom_score_adj;
    char process_name[kTaskCommLen];
};

class MemEventListener final {
  public:
    MemEventListener();
    ~MemEventListener();

    /**
     * Registers the requested memory event to the listener. File
     * descriptor gets attached to the `mEpfd`.
     *
     * Will create a new epoll instance (epfd) if one hasn't been created.
     *
     * @param event_type Memory event type to listen for.
     * @return true if registration was successful, false otherwise.
     */
    bool registerEvent(MemEvent event_type);

    /**
     * Waits for a [registered] memory event notification.
     *
     * @return memory event type that has [new] unread entries.
     */
    MemEvent listen();

    /**
     * Stops listening for a specific memory event type.
     *
     * In the case we deregister the only/last registered event, we also
     * close the `mEpfd` and terminate any ongoing `listen()`.
     *
     * @param event_type Memory event type to stop listening to.
     * @return true if unregistering was successful, false otherwise
     */
    bool deregisterEvent(MemEvent event_type);

    /**
     * Closes all the events' file descriptors and `mEpfd`. This will also
     * gracefully terminate any ongoing `listen()`.
     */
    void deregisterAllEvents();

    /**
     * Retrieves unread OOM events, and stores them into the
     * provided `oom_events` vector.
     *
     * On first invocation, it will read/store all the entries from the
     * OOM's event file. After the initial invocation, it will only
     * read/store new, unread, events.
     *
     * @param oom_events vector in which we want to append the read OOM
     * events.
     * @return true on success, false on failure.
     */
    bool getOomEvents(std::vector<OomKill>& oom_events);

  private:
    int mEpfd;
    int mFds[NR_MEM_EVENTS];
    std::deque<MemEvent> mPendingEvents;

    bool readOomFile(int fd, std::vector<OomKill>& oom_events);
    bool isValidEventType(MemEvent event_type);
};

}  // namespace memevents
}  // namespace android