#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sec::behavior {

enum class EventType { Exec, Fork, Exit, FileCreate, FileModify, FileRename, NetConnect, DnsQuery };

const char* to_string(EventType t);

// A process as reported by a sensor.
struct ProcessRef {
    int pid = 0;
    int ppid = 0;
    std::string path;
    std::vector<std::string> args;  // argv (Exec only)
    std::vector<std::string> env;   // interesting environment entries only ("DYLD_*", "LD_PRELOAD"); Exec only
    std::string signing_id;
    std::string team_id;
    bool platform_binary = false;  // shipped with macOS
    bool sig_known = false;        // false when the sensor did not report signing info
};

struct Event {
    EventType type = EventType::Exec;
    std::int64_t time_ms = 0;  // epoch milliseconds
    // Exec: the new process image. Fork: the new child. Others: the acting process.
    ProcessRef proc;
    std::string file_path;  // FileCreate/FileModify: the file; FileRename: the new path
    std::string file_from;  // FileRename: the old path
    std::string remote_ip;
    int remote_port = 0;
    std::string remote_host;  // empty if unknown
    std::string dns_name;
};

}
