#pragma once

#include "behavior/alert_store.h"
#include "behavior/engine.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace sec::sensor {

struct SensorStats {
    std::uint64_t events_in = 0;       // accepted into the queue
    std::uint64_t events_dropped = 0;  // queue full
    std::uint64_t events_ignored = 0;  // filtered (own process, noisy paths)
    std::uint64_t events_processed = 0;
    std::uint64_t alerts = 0;
};

// Owns the behaviour engine and a worker thread. Sensors call submit() from any thread.
class SensorService {
public:
    using AlertCallback = std::function<void(const behavior::Alert&)>;

    SensorService(behavior::RuleSet rules, behavior::IocSet ioc, behavior::AlertLog* log, AlertCallback on_alert = {});
    ~SensorService();
    SensorService(const SensorService&) = delete;
    SensorService& operator=(const SensorService&) = delete;

    void start();
    void stop();

    // Never blocks. Events from ignored processes or noisy paths are dropped quietly.
    void submit(behavior::Event ev);

    // Events from this pid (e.g. the eslogger child) are ignored. 0 clears it.
    void set_extra_ignored_pid(int pid) { extra_ignored_pid_ = pid; }

    // Waits until everything submitted so far has been processed (used by tests and --source stdin).
    void flush();

    SensorStats stats() const;

    static constexpr std::size_t kMaxQueue = 200000;

private:
    void run();
    bool is_noisy_file(const std::string& path) const;

    behavior::Engine engine_;
    behavior::AlertLog* log_;
    AlertCallback on_alert_;
    int self_pid_;
    std::atomic<int> extra_ignored_pid_{0};

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::condition_variable idle_cv_;
    std::deque<behavior::Event> queue_;
    bool busy_ = false;
    bool stop_ = false;
    bool running_ = false;
    std::thread worker_;
    std::int64_t last_time_ms_ = 0;

    std::atomic<std::uint64_t> in_{0}, dropped_{0}, ignored_{0}, processed_{0}, alerts_{0};
};

}
