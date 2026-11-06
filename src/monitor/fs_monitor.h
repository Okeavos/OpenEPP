#pragma once

#include <filesystem>
#include <functional>
#include <memory>
#include <vector>

namespace sec {

// File-event source (macOS FSEvents). Calls the callback, from a background thread, for every
// created / modified / renamed regular file below the watched roots (recursive).
class FsMonitor {
public:
    using Callback = std::function<void(const std::filesystem::path&)>;

    struct Impl;

    FsMonitor();
    ~FsMonitor();
    FsMonitor(const FsMonitor&) = delete;
    FsMonitor& operator=(const FsMonitor&) = delete;

    // Roots that do not exist are skipped. Returns false if nothing could be watched.
    bool start(const std::vector<std::filesystem::path>& roots, Callback callback);
    void stop();
    bool running() const { return impl_ != nullptr; }

private:
    std::unique_ptr<Impl> impl_;
};

}
