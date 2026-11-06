#pragma once

#include "agent/agent.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <map>
#include <mutex>
#include <thread>
#include <vector>

namespace sec {

struct RealtimeStats {
    std::uint64_t events = 0;   // notify() calls accepted
    std::uint64_t scanned = 0;  // files actually scanned
};

// Platform-neutral real-time scan queue. A platform file-event source (FSEvents on macOS)
// calls notify(); events for the same path are coalesced until the file has been quiet for
// `debounce`, so files that are still being written/downloaded are scanned once, at the end.
class RealtimeScanner {
public:
    explicit RealtimeScanner(Agent& agent,
                             std::chrono::milliseconds debounce = std::chrono::milliseconds(1500));
    ~RealtimeScanner();

    RealtimeScanner(const RealtimeScanner&) = delete;
    RealtimeScanner& operator=(const RealtimeScanner&) = delete;

    // Events for paths below this directory are dropped (e.g. our own data/quarantine dir).
    void add_ignore_prefix(const std::filesystem::path& dir);

    void start();
    void stop();

    // Thread-safe; cheap.
    void notify(const std::filesystem::path& path);

    void set_paused(bool paused) { paused_ = paused; }
    bool paused() const { return paused_.load(); }

    RealtimeStats stats() const;

private:
    void run();
    void scan_one(const std::filesystem::path& path);
    bool ignored(const std::filesystem::path& path) const;

    Agent& agent_;
    std::chrono::milliseconds debounce_;

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::map<std::filesystem::path, std::chrono::steady_clock::time_point> pending_;
    std::vector<std::filesystem::path> ignore_prefixes_;
    bool stop_ = false;
    std::thread worker_;

    std::atomic<bool> paused_{false};
    std::atomic<std::uint64_t> events_{0};
    std::atomic<std::uint64_t> scanned_{0};
};

}
