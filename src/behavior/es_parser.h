#pragma once

#include "behavior/event.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace sec::behavior {

struct ParseResult {
    enum class Status { Ok, Skipped, Error };
    Status status = Status::Skipped;
    Event event;
    std::string error;  // set when status == Error

    bool ok() const { return status == Status::Ok; }
};

// One JSON line produced by `eslogger` (macOS 13+). Supported: exec, fork, exit, create, rename,
// close (only when modified). Other event types are Skipped. The field layout follows Apple's
// es_message_t JSON rendering; verify against a real capture on your macOS version.
ParseResult parse_eslogger_line(std::string_view line);

// One JSON line in Sec's own normalized format (used by network/DNS sensors, tests and scenarios):
//   {"type":"exec","time_ms":1000,"pid":10,"ppid":1,"path":"/bin/sh","args":["sh","-c","id"],"signing":"platform"}
//   {"type":"fork","pid":11,"ppid":10}
//   {"type":"exit","pid":11}
//   {"type":"file_create"|"file_modify"|"file_rename","pid":..,"path":..(actor),"file":"/new","from":"/old"}
//   {"type":"net","pid":..,"path":..,"remote_ip":"1.2.3.4","remote_port":443,"remote_host":"example.com"}
//   {"type":"dns","pid":..,"path":..,"dns_name":"example.com"}
// "signing": "platform" | "unsigned" | "adhoc" | "team:<TEAMID>" | omitted (unknown).
ParseResult parse_normalized_line(std::string_view line);

// Detects the format (eslogger lines have an "event" object) and dispatches.
ParseResult parse_event_line(std::string_view line);

// "2026-11-05T12:34:56.789Z" -> epoch milliseconds. Returns nullopt for unparsable input.
std::optional<std::int64_t> parse_iso8601_ms(std::string_view s);

}
