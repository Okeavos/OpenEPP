#include "sensor/conn_tracker.h"

#include "behavior/net_util.h"

namespace sec::sensor {

namespace {

bool is_loopback(const std::string& ip) {
    return ip.rfind("127.", 0) == 0 || ip == "::1" || ip == "::ffff:127.0.0.1";
}

}

std::vector<behavior::Event> ConnTracker::update(const std::vector<ConnInfo>& snapshot, std::int64_t now_ms) {
    std::vector<behavior::Event> out;
    std::set<std::string> current;

    for (const ConnInfo& c : snapshot) {
        if (c.pid <= 0 || c.remote_ip.empty() || c.remote_port <= 0 || is_loopback(c.remote_ip)) continue;
        const std::string key = std::to_string(c.pid) + "|" + std::to_string(c.local_port) + "|" + c.remote_ip + "|" +
                                std::to_string(c.remote_port);
        current.insert(key);
        if (known_.count(key) != 0) continue;
        if (first_ && !emit_initial_) continue;

        behavior::Event ev;
        ev.type = behavior::EventType::NetConnect;
        ev.time_ms = now_ms;
        ev.proc.pid = c.pid;
        ev.proc.ppid = c.ppid;
        ev.proc.path = c.path;
        ev.remote_ip = c.remote_ip;
        ev.remote_port = c.remote_port;
        out.push_back(std::move(ev));
    }
    known_ = std::move(current);
    first_ = false;
    return out;
}

}
