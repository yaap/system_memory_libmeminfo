#include <fcntl.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <sstream>
#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>

#include <memevents/memevents.h>

namespace android {
namespace memevents {

static const char* kMemHealthDir = "/proc/memhealth";

MemEventListener::MemEventListener() {
    mEpfd = -1;
    std::fill_n(mFds, NR_MEM_EVENTS, -1);
}

MemEventListener::~MemEventListener() {
    deregisterAllEvents();
}

/**
 * Read the content of OOM file descriptor, and parse the buffer to
 * save OOM event data into `oom_events`.
 *
 * The `content` string contains multiple lines, where each line represents
 * an OOM kill event.
 * Each line contains four space-separated values in the order of:
 * timestamp (milli), PID, UID, oom_score_adj, and process name.
 *
 * @param fd file descriptor of the oom events file to read.
 * @param oom_events vector in which we want to add the new OOM events.
 * @return true on success, false on read failure.
 */
bool MemEventListener::readOomFile(int fd, std::vector<OomKill>& oom_events) {
    const int total_fields = 5;
    const std::string fmt = "%llu %d %lu %i %" + std::to_string(kTaskCommLen - 1) + "s";

    std::string content;
    if (!android::base::ReadFdToString(fd, &content)) {
        LOG(ERROR) << "memevent failed to read OOM event file";
        return false;
    }

    std::stringstream ss(content);
    std::string line;
    while (std::getline(ss, line)) {
        struct OomKill oom_event;
        if (!line.empty() && sscanf(line.c_str(), fmt.c_str(), &oom_event.timestamp_ms,
                                    &oom_event.pid, &oom_event.uid, &oom_event.oom_score_adj,
                                    oom_event.process_name) == total_fields) {
            oom_events.push_back(oom_event);
        } else {
            LOG(WARNING) << "memevents skipping invalid formatted OOM line: " << line;
        }
    }
    return true;
}

/**
 * Helper function that determines if an event type is valid.
 * We define "valid" as an actual event type that we can listen and register to.
 *
 * @param event_type memory event type to validate.
 * @return true if it's less than `NR_MEM_EVENTS` and greater than
 * `ERROR`.
 */
bool MemEventListener::isValidEventType(MemEvent event_type) {
    return event_type < MemEvent::NR_MEM_EVENTS && event_type > MemEvent::ERROR;
}

// Public methods
bool MemEventListener::registerEvent(MemEvent event_type) {
    if (!isValidEventType(event_type)) {
        LOG(ERROR) << "memevent register failed, received invalid event type";
        return false;
    }
    if (mFds[event_type] != -1) {
        // We are already registered to this event
        return true;
    }
    if (mEpfd < 0) {
        mEpfd = TEMP_FAILURE_RETRY(epoll_create(NR_MEM_EVENTS));
        if (mEpfd < 0) {
            PLOG(ERROR) << "memevent failed creating epfd";
            return false;
        }
    }

    std::string event_file = std::string(kMemHealthDir);
    switch (event_type) {
        case OOM_KILL:
            event_file += "/oom_victim_list";
            break;
        default:
            /*
             * We never get here since we verify the event type with
             * `isValidEventType()`, no log needed
             */
            return false;
    }
    int fd = TEMP_FAILURE_RETRY(open(event_file.c_str(), O_RDONLY | O_CLOEXEC));
    if (fd < 0) {
        PLOG(ERROR) << "memevent registerEvent failed to open file: " << event_file;
        return false;
    }

    struct epoll_event event = {
            .events = EPOLLPRI,
            .data =
                    {
                            .fd = fd,
                            .u32 = static_cast<uint32_t>(event_type),
                    },
    };
    if (epoll_ctl(mEpfd, EPOLL_CTL_ADD, fd, &event) < 0) {
        PLOG(ERROR) << "epoll_ctl for memevent failed adding fd: " << fd;
        close(fd);
        return false;
    }

    mFds[event_type] = fd;
    return true;
}

MemEvent MemEventListener::listen() {
    if (mEpfd < 0) {
        LOG(ERROR) << "memevent listen failed, invalid epfd:" << mEpfd;
        return MemEvent::ERROR;
    }

    if (mPendingEvents.empty()) {
        /*
         * Wait for memory events to occur, and store the event types received
         * in `mPendingEvents`
         */
        struct epoll_event events[NR_MEM_EVENTS];
        int num_events = TEMP_FAILURE_RETRY(epoll_wait(mEpfd, events, NR_MEM_EVENTS, -1));
        if (num_events < 0) {
            PLOG(ERROR) << "memevent listen failed while waiting for events";
            return MemEvent::ERROR;
        }

        for (int i = 0; i < num_events; i++) {
            if (events[i].events & EPOLLPRI) {
                auto event_type = static_cast<MemEvent>(events[i].data.u32);
                mPendingEvents.push_back(event_type);
            }
        }
    }

    MemEvent event = mPendingEvents.front();
    mPendingEvents.pop_front();
    return event;
}

bool MemEventListener::deregisterEvent(MemEvent event_type) {
    if (!isValidEventType(event_type)) {
        LOG(ERROR) << "memevent failed to deregister, invalid event type";
        return false;
    }
    int fd = mFds[event_type];
    if (fd == -1) {
        LOG(INFO) << "memevent received event type that is not registered";
        return true;
    }
    if (epoll_ctl(mEpfd, EPOLL_CTL_DEL, fd, NULL) < 0) {
        PLOG(ERROR) << "memevent deregister failed to remove fd: " << fd;
        return false;
    }
    close(fd);
    mFds[event_type] = -1;

    bool areAllFdsClosed = true;
    for (int i = 0; i < MemEvent::NR_MEM_EVENTS; i++) {
        if (mFds[i] > -1) {
            areAllFdsClosed = false;
            break;
        }
    }
    if (areAllFdsClosed) {
        /*
         * Close the epfd to prevent calling `listen()` on an epty epfd.
         * Since performing the `listen()`, with no registered events, will
         * cause us to wait forever.
         */
        close(mEpfd);
        mEpfd = -1;
    }

    return true;
}

void MemEventListener::deregisterAllEvents() {
    if (mEpfd < 0) return;
    for (int i = 0; i < NR_MEM_EVENTS; i++) {
        if (mFds[i] != -1) deregisterEvent(static_cast<MemEvent>(i));
    }
    /*
     * `deregisterEvent` handles closing/resetting the `mEpfd`, after closing
     * the last open event, therefore we don't need close anything here.
     */
}

bool MemEventListener::getOomEvents(std::vector<OomKill>& oom_events) {
    int oom_fd = mFds[OOM_KILL];
    if (oom_fd < 0) {
        LOG(ERROR) << "oom event has not been initialized in memevent listener";
        return false;
    }
    return readOomFile(oom_fd, oom_events);
}

}  // namespace memevents
}  // namespace android