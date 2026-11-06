#include "agent/realtime.h"

#include "common/log.h"
#include "common/util.h"

#include <algorithm>

namespace fs = std::filesystem;

namespace sec {

namespace {

bool is_under(const fs::path& path, const fs::path& base) {
    const auto [a, b] = std::mismatch(base.begin(), base.end(), path.begin(), path.end());
    (void)b;
    return a == base.end();
}

bool is_noise(const fs::path& path) {
    const std::string name = util::to_lower(util::path_to_utf8(path.filename()));
    if (name == ".ds_store") return true;
    for (const char* ext : {".crdownload", ".download", ".part", ".partial", ".tmp"}) {
        const std::string e = ext;
        if (name.size() >= e.size() && name.compare(name.size() - e.size(), e.size(), e) == 0) return true;
    }
    return false;
}

}

RealtimeScanner::RealtimeScanner(Agent& agent, std::chrono::milliseconds debounce)
    : agent_(agent), debounce_(debounce) {}

RealtimeScanner::~RealtimeScanner() { stop(); }

void RealtimeScanner::add_ignore_prefix(const fs::path& dir) {
    std::error_code ec;
    const fs::path canonical = fs::weakly_canonical(dir, ec);
    const fs::path lexical = dir.lexically_normal();
    std::lock_guard<std::mutex> lock(mutex_);
    ignore_prefixes_.push_back(lexical);
    if (!ec && canonical != lexical) ignore_prefixes_.push_back(canonical);
}

void RealtimeScanner::start() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (worker_.joinable()) return;
    stop_ = false;
    worker_ = std::thread([this] { run(); });
}

void RealtimeScanner::stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!worker_.joinable()) return;
        stop_ = true;
    }
    cv_.notify_all();
    worker_.join();
}

bool RealtimeScanner::ignored(const fs::path& path) const {
    if (is_noise(path)) return true;
    for (const fs::path& prefix : ignore_prefixes_) {
        if (is_under(path, prefix)) return true;
    }
    return false;
}

void RealtimeScanner::notify(const fs::path& path) {
    if (paused_.load()) return;
    const fs::path p = path.lexically_normal();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (ignored(p)) return;
        pending_[p] = std::chrono::steady_clock::now();
    }
    ++events_;
    cv_.notify_one();
}

RealtimeStats RealtimeScanner::stats() const {
    RealtimeStats s;
    s.events = events_.load();
    s.scanned = scanned_.load();
    return s;
}

void RealtimeScanner::run() {
    std::unique_lock<std::mutex> lock(mutex_);
    while (!stop_) {
        const auto now = std::chrono::steady_clock::now();
        std::vector<fs::path> ready;
        bool have_deadline = false;
        std::chrono::steady_clock::time_point deadline;
        for (auto it = pending_.begin(); it != pending_.end();) {
            const auto due = it->second + debounce_;
            if (due <= now) {
                ready.push_back(it->first);
                it = pending_.erase(it);
            } else {
                if (!have_deadline || due < deadline) deadline = due;
                have_deadline = true;
                ++it;
            }
        }

        if (!ready.empty()) {
            lock.unlock();
            for (const fs::path& p : ready) {
                if (stop_) break;
                scan_one(p);
            }
            lock.lock();
            continue;
        }

        if (have_deadline) {
            cv_.wait_until(lock, deadline);
        } else {
            cv_.wait(lock);
        }
    }
}

void RealtimeScanner::scan_one(const fs::path& path) {
    std::error_code ec;
    if (!fs::is_regular_file(path, ec) || ec) return;

    const ScanResult r = agent_.engine().scan_file(path);
    if (r.verdict == Verdict::Skipped || r.verdict == Verdict::Error) return;
    ++scanned_;
    if (r.verdict == Verdict::Malicious || r.verdict == Verdict::Suspicious) agent_.handle_detection(r);
}

}
