#include "behavior/event.h"

namespace sec::behavior {

const char* to_string(EventType t) {
    switch (t) {
        case EventType::Exec: return "exec";
        case EventType::Fork: return "fork";
        case EventType::Exit: return "exit";
        case EventType::FileCreate: return "file_create";
        case EventType::FileModify: return "file_modify";
        case EventType::FileRename: return "file_rename";
        case EventType::NetConnect: return "net_connect";
        case EventType::DnsQuery: return "dns_query";
    }
    return "?";
}

}
