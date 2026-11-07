#include "sensor/sensor_service.h"

#include "common/log.h"

#include <algorithm>

#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#endif

namespace sec::sensor {

namespace {

int current_pid() {
#if defined(_WIN32)
    return _getpid();
#else
    return static_cast<int>(::getpid());
#endif
}

bool starts_with(const std::string& s, const char* p) { return s.rfind(p, 0) == 0; }

bool contains(const std::string& s, const char* p) { return s.find(p) != std::string::npos; }

}

SensorService::SensorService(behavior::RuleSet rules, behavior::IocSet ioc, behavior::AlertLog* log,
                             AlertCallback on_alert)
    : engine_(std::move(rules)), log_(log), on_alert_(std::move(on_alert)), self_pid_(current_pid()) {
    engine_.set_ioc(std::move(ioc));
}

SensorService::~SensorService() { stop(); }

void SensorService::start() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (running_) return;
    stop_ = false;
    running_ = true;
    worker_ = std::thread([this] { run(); });
}

void SensorService::stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stop_ = true;
    }
    cv_.notify_all();
    if (worker_.joinable()) worker_.join();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        running_ = false;
    }
    idle_cv_.notify_all();
}

bool SensorService::is_noisy_file(const std::string& path) const {
    // High-volume locations that no rule cares about; skipping them keeps the queue small.
    return starts_with(path, "/System/") || starts_with(path, "/dev/") || starts_with(path, "/private/var/db/") ||
           starts_with(path, "/private/var/log/") || starts_with(path, "/private/var/vm/") ||
           starts_with(path, "/Library/Caches/") || contains(path, "/Library/Caches/") ||
           contains(path, "/Library/Logs/") || contains(path, "/Library/Application Support/SecEPP/") ||
           contains(path, "/.Spotlight-V100/") || contains(path, "/.fseventsd/");
}

void SensorService::submit(behavior::Event ev) {
    const int pid = ev.proc.pid;
    if (pid == self_pid_ || (pid != 0 && pid == extra_ignored_pid_.load())) {
        ++ignored_;
        return;
    }
    const bool file_event = ev.type == behavior::EventType::FileCreate ||
                            ev.type == behavior::EventType::FileModify || ev.type == behavior::EventType::FileRename;
    if (file_event && is_noisy_file(ev.file_path)) {
        ++ignored_;
        return;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.size() >= kMaxQueue) {
            ++dropped_;
            return;
        }
        queue_.push_back(std::move(ev));
    }
    ++in_;
    cv_.notify_one();
}

void SensorService::seed_processes(std::vector<behavior::ProcessRef> procs) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (behavior::ProcessRef& p : procs) pending_seeds_.push_back(std::move(p));
    }
    cv_.notify_one();
}

void SensorService::flush() {
    std::unique_lock<std::mutex> lock(mutex_);
    idle_cv_.wait(lock, [this] { return (queue_.empty() && pending_seeds_.empty() && !busy_) || !running_; });
}

SensorStats SensorService::stats() const {
    SensorStats s;
    s.events_in = in_;
    s.events_dropped = dropped_;
    s.events_ignored = ignored_;
    s.events_processed = processed_;
    s.alerts = alerts_;
    s.suppressed = suppressed_;
    s.seeded = seeded_;
    return s;
}

void SensorService::run() {
    while (true) {
        behavior::Event ev;
        std::vector<behavior::ProcessRef> seeds;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this] { return stop_ || !queue_.empty() || !pending_seeds_.empty(); });
            if (!pending_seeds_.empty()) {
                seeds.swap(pending_seeds_);
                busy_ = true;
            } else if (queue_.empty()) {
                idle_cv_.notify_all();
                if (stop_) return;
                continue;
            } else {
                ev = std::move(queue_.front());
                queue_.pop_front();
                busy_ = true;
            }
        }

        if (!seeds.empty()) {
            const std::int64_t t = std::max(last_time_ms_, behavior::now_ms());
            for (const behavior::ProcessRef& p : seeds) engine_.seed_process(p, t);
            seeded_ = engine_.seeded();
            std::lock_guard<std::mutex> lock(mutex_);
            busy_ = false;
            if (queue_.empty() && pending_seeds_.empty()) idle_cv_.notify_all();
            continue;
        }

        // Sensors run on different clocks and threads; the engine expects non-decreasing time.
        if (ev.time_ms <= 0) ev.time_ms = behavior::now_ms();
        if (ev.time_ms < last_time_ms_) ev.time_ms = last_time_ms_;
        last_time_ms_ = ev.time_ms;

        std::vector<behavior::Alert> alerts = engine_.process(ev);
        ++processed_;
        suppressed_ = engine_.suppressed();
        if (event_hook_) event_hook_(ev, alerts.size());
        for (behavior::Alert& a : alerts) {
            if (enricher_) enricher_(a);
            ++alerts_;
            if (log_ != nullptr && !log_->append(a)) log::error("cannot write alert log");
            if (on_alert_) on_alert_(a);
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            busy_ = false;
            if (queue_.empty() && pending_seeds_.empty()) idle_cv_.notify_all();
        }
    }
}

}
