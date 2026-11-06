#include "monitor/fs_monitor.h"

#include <CoreServices/CoreServices.h>
#include <dispatch/dispatch.h>

#include <mutex>
#include <utility>

namespace fs = std::filesystem;

namespace sec {

struct FsMonitor::Impl {
    FSEventStreamRef stream = nullptr;
    dispatch_queue_t queue = nullptr;
    Callback callback;
    std::mutex gate;
    bool active = true;
};

namespace {

void on_events(ConstFSEventStreamRef, void* info, size_t count, void* event_paths,
               const FSEventStreamEventFlags flags[], const FSEventStreamEventId[]) {
    auto* impl = static_cast<FsMonitor::Impl*>(info);
    const char* const* paths = static_cast<const char* const*>(event_paths);
    constexpr FSEventStreamEventFlags kWanted = kFSEventStreamEventFlagItemCreated |
                                                kFSEventStreamEventFlagItemModified |
                                                kFSEventStreamEventFlagItemRenamed;

    std::lock_guard<std::mutex> lock(impl->gate);
    if (!impl->active || !impl->callback) return;
    for (size_t i = 0; i < count; ++i) {
        const FSEventStreamEventFlags f = flags[i];
        if (!(f & kFSEventStreamEventFlagItemIsFile)) continue;
        if (!(f & kWanted)) continue;
        impl->callback(fs::path(paths[i]));
    }
}

}

FsMonitor::FsMonitor() = default;

FsMonitor::~FsMonitor() { stop(); }

bool FsMonitor::start(const std::vector<fs::path>& roots, Callback callback) {
    stop();

    CFMutableArrayRef array = CFArrayCreateMutable(nullptr, 0, &kCFTypeArrayCallBacks);
    size_t watched = 0;
    for (const fs::path& root : roots) {
        std::error_code ec;
        if (!fs::is_directory(root, ec)) continue;
        CFStringRef s = CFStringCreateWithCString(nullptr, root.c_str(), kCFStringEncodingUTF8);
        if (s == nullptr) continue;
        CFArrayAppendValue(array, s);
        CFRelease(s);
        ++watched;
    }
    if (watched == 0) {
        CFRelease(array);
        return false;
    }

    auto impl = std::make_unique<Impl>();
    impl->callback = std::move(callback);

    FSEventStreamContext ctx = {0, impl.get(), nullptr, nullptr, nullptr};
    impl->stream = FSEventStreamCreate(nullptr, &on_events, &ctx, array, kFSEventStreamEventIdSinceNow, 0.5,
                                       kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer);
    CFRelease(array);
    if (impl->stream == nullptr) return false;

    impl->queue = dispatch_queue_create("com.sec.epp.fsevents", DISPATCH_QUEUE_SERIAL);
    FSEventStreamSetDispatchQueue(impl->stream, impl->queue);
    if (!FSEventStreamStart(impl->stream)) {
        FSEventStreamInvalidate(impl->stream);
        FSEventStreamRelease(impl->stream);
        dispatch_release(impl->queue);
        return false;
    }

    impl_ = std::move(impl);
    return true;
}

void FsMonitor::stop() {
    if (!impl_) return;
    FSEventStreamStop(impl_->stream);
    FSEventStreamInvalidate(impl_->stream);
    FSEventStreamRelease(impl_->stream);
    {
        std::lock_guard<std::mutex> lock(impl_->gate);
        impl_->active = false;
    }
    dispatch_release(impl_->queue);
    impl_.reset();
}

}
