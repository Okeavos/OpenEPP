#include "sensor/socket_poller.h"

#include "behavior/alert_store.h"
#include "common/log.h"

#include <chrono>

namespace sec::sensor {

SocketPoller::SocketPoller(SnapshotFn snapshot, int interval_ms, SensorService& service)
    : snapshot_(std::move(snapshot)), interval_ms_(interval_ms < 100 ? 100 : interval_ms), service_(service) {}

SocketPoller::~SocketPoller() { stop(); }

void SocketPoller::start() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (thread_.joinable()) return;
    stop_ = false;
    state_ = "running";
    thread_ = std::thread([this] { run(); });
}

void SocketPoller::stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stop_ = true;
    }
    cv_.notify_all();
    if (thread_.joinable()) thread_.join();
    std::lock_guard<std::mutex> lock(mutex_);
    state_ = "stopped";
}

std::string SocketPoller::state() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_;
}

void SocketPoller::run() {
    while (true) {
        std::vector<ConnInfo> snap;
        const bool ok = snapshot_ && snapshot_(snap);
        ++polls_;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stop_) return;
            state_ = ok ? "running" : "failed";
        }
        if (ok) {
            for (behavior::Event& ev : tracker_.update(snap, behavior::now_ms())) service_.submit(std::move(ev));
        }

        std::unique_lock<std::mutex> lock(mutex_);
        if (cv_.wait_for(lock, std::chrono::milliseconds(interval_ms_), [this] { return stop_; })) return;
    }
}

}
