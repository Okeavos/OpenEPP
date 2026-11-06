#pragma once

#include "behavior/event.h"

#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace sec::sensor {

struct ConnInfo {
    int pid = 0;
    int ppid = 0;
    std::string path;  // process image, may be empty
    std::string remote_ip;
    int remote_port = 0;
    int local_port = 0;
};

// Turns periodic "all current TCP connections" snapshots into one NetConnect event per new connection.
class ConnTracker {
public:
    // emit_initial=false: connections that already exist at the first snapshot are only remembered.
    explicit ConnTracker(bool emit_initial = false) : emit_initial_(emit_initial) {}

    std::vector<behavior::Event> update(const std::vector<ConnInfo>& snapshot, std::int64_t now_ms);

    std::size_t tracked() const { return known_.size(); }

private:
    bool emit_initial_;
    bool first_ = true;
    std::set<std::string> known_;
};

}
