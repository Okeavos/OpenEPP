#pragma once

#include "sensor/conn_tracker.h"
#include "sensor/sensor_service.h"

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace sec::sensor {

// Fills `out` with every current TCP connection. Returns false if the platform call failed.
using SnapshotFn = std::function<bool(std::vector<ConnInfo>& out)>;

#if defined(__APPLE__)
// libproc based snapshot (src/sensor/socket_snapshot_mac.cpp).
bool snapshot_tcp_connections_mac(std::vector<ConnInfo>& out);
#endif

class SocketPoller {
public:
    SocketPoller(SnapshotFn snapshot, int interval_ms, SensorService& service);
    ~SocketPoller();
    SocketPoller(const SocketPoller&) = delete;
    SocketPoller& operator=(const SocketPoller&) = delete;

    void start();
    void stop();

    // "running" | "failed" | "stopped"
    std::string state() const;
    std::uint64_t polls() const { return polls_; }

private:
    void run();

    SnapshotFn snapshot_;
    int interval_ms_;
    SensorService& service_;
    ConnTracker tracker_;
    std::thread thread_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    bool stop_ = false;
    std::string state_ = "stopped";
    std::atomic<std::uint64_t> polls_{0};
};

}
