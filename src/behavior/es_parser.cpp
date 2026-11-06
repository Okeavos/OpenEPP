#include "behavior/es_parser.h"

#include "common/json.h"
#include "common/util.h"

namespace sec::behavior {

namespace {

using json::Value;

ParseResult skipped() { return ParseResult{}; }

ParseResult error(std::string msg) {
    ParseResult r;
    r.status = ParseResult::Status::Error;
    r.error = std::move(msg);
    return r;
}

ParseResult ok(Event ev) {
    ParseResult r;
    r.status = ParseResult::Status::Ok;
    r.event = std::move(ev);
    return r;
}

// es_file_t is rendered as {"path": "...", ...}; accept a bare string as well.
std::string file_path_of(const Value& v) {
    if (v.is_string()) return v.as_string();
    return v["path"].as_string();
}

ProcessRef es_process(const Value& p) {
    ProcessRef r;
    r.pid = static_cast<int>(p["audit_token"]["pid"].as_int());
    if (r.pid == 0) r.pid = static_cast<int>(p["pid"].as_int());
    r.ppid = static_cast<int>(p["ppid"].as_int());
    r.path = file_path_of(p["executable"]);
    r.signing_id = p["signing_id"].as_string();
    r.team_id = p["team_id"].as_string();
    r.platform_binary = p["is_platform_binary"].as_bool();
    r.sig_known = p.find("signing_id") != nullptr || p.find("team_id") != nullptr ||
                  p.find("is_platform_binary") != nullptr || p.find("codesigning_flags") != nullptr;
    return r;
}

// es_event_create/rename destinations: {"existing_file": {...}} or {"new_path": {"dir": {...}, "filename": "x"}}
std::string es_destination(const Value& ev) {
    const Value& d = ev["destination"];
    if (const Value* existing = d.find("existing_file")) return file_path_of(*existing);
    if (const Value* np = d.find("new_path")) {
        std::string dir = file_path_of((*np)["dir"]);
        const std::string name = (*np)["filename"].as_string();
        if (dir.empty()) return name;
        if (dir.back() != '/') dir.push_back('/');
        return dir + name;
    }
    return std::string();
}

std::int64_t event_time(const Value& root) {
    if (const Value* t = root.find("time")) {
        if (t->is_string()) {
            if (const auto ms = parse_iso8601_ms(t->as_string())) return *ms;
        } else if (t->is_number()) {
            return t->as_int();
        }
    }
    return 0;
}

ProcessRef normalized_process(const Value& v) {
    ProcessRef r;
    r.pid = static_cast<int>(v["pid"].as_int());
    r.ppid = static_cast<int>(v["ppid"].as_int());
    r.path = v["path"].as_string();
    if (const Value* args = v.find("args")) {
        if (args->is_array()) {
            for (const Value& a : args->items()) r.args.push_back(a.as_string());
        }
    }
    const std::string sg = v["signing"].as_string();
    if (sg == "platform") {
        r.sig_known = true;
        r.platform_binary = true;
    } else if (sg == "unsigned" || sg == "adhoc") {
        r.sig_known = true;
    } else if (sg.rfind("team:", 0) == 0) {
        r.sig_known = true;
        r.team_id = sg.substr(5);
    }
    return r;
}

}

std::optional<std::int64_t> parse_iso8601_ms(std::string_view s) {
    // YYYY-MM-DDTHH:MM:SS[.fraction][Z|+hh:mm|-hh:mm]
    auto num = [&](std::size_t pos, std::size_t len) -> int {
        if (pos + len > s.size()) return -1;
        int v = 0;
        for (std::size_t i = 0; i < len; ++i) {
            const char c = s[pos + i];
            if (c < '0' || c > '9') return -1;
            v = v * 10 + (c - '0');
        }
        return v;
    };
    if (s.size() < 19 || s[4] != '-' || s[7] != '-' || (s[10] != 'T' && s[10] != ' ') || s[13] != ':' ||
        s[16] != ':') {
        return std::nullopt;
    }
    const int y = num(0, 4), mo = num(5, 2), d = num(8, 2), h = num(11, 2), mi = num(14, 2), se = num(17, 2);
    if (y < 0 || mo < 1 || mo > 12 || d < 1 || d > 31 || h < 0 || h > 23 || mi < 0 || mi > 59 || se < 0 || se > 60) {
        return std::nullopt;
    }

    std::size_t pos = 19;
    std::int64_t ms = 0;
    if (pos < s.size() && s[pos] == '.') {
        ++pos;
        int digits = 0;
        while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9') {
            if (digits < 3) ms = ms * 10 + (s[pos] - '0');
            ++digits;
            ++pos;
        }
        if (digits == 0) return std::nullopt;
        for (int i = digits; i < 3; ++i) ms *= 10;
    }
    std::int64_t offset_s = 0;
    if (pos < s.size()) {
        if (s[pos] == 'Z') {
            ++pos;
        } else if (s[pos] == '+' || s[pos] == '-') {
            const int sign = s[pos] == '+' ? 1 : -1;
            const int oh = num(pos + 1, 2);
            int om = 0;
            std::size_t next = pos + 3;
            if (next < s.size() && s[next] == ':') ++next;
            om = num(next, 2);
            if (oh < 0 || om < 0) return std::nullopt;
            offset_s = sign * (oh * 3600 + om * 60);
            pos = next + 2;
        }
    }
    if (pos != s.size()) return std::nullopt;

    // days from civil (Howard Hinnant)
    const std::int64_t yy = mo <= 2 ? y - 1 : y;
    const std::int64_t era = (yy >= 0 ? yy : yy - 399) / 400;
    const std::int64_t yoe = yy - era * 400;
    const std::int64_t doy = (153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const std::int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const std::int64_t days = era * 146097 + doe - 719468;
    return ((days * 86400 + h * 3600 + mi * 60 + se) - offset_s) * 1000 + ms;
}

ParseResult parse_eslogger_line(std::string_view line) {
    // `close` events are by far the most frequent; skip unmodified ones before the (expensive) JSON parse.
    const std::size_t mod = line.find("\"modified\"");
    if (mod != std::string_view::npos) {
        std::size_t i = mod + 10;
        while (i < line.size() && (line[i] == ' ' || line[i] == ':')) ++i;
        if (line.compare(i, 5, "false") == 0) return skipped();
    }
    std::string perr;
    const auto doc = json::parse(line, &perr);
    if (!doc || !doc->is_object()) return error("invalid JSON: " + perr);

    const Value& ev = (*doc)["event"];
    if (!ev.is_object() || ev.keys().empty()) return error("missing 'event' object");

    Event out;
    out.time_ms = event_time(*doc);
    const std::string& kind = ev.keys().front();
    const Value& body = ev.items().front();

    if (kind == "exec") {
        out.type = EventType::Exec;
        out.proc = es_process(body["target"]);
        if (const Value* args = body.find("args")) {
            if (args->is_array()) {
                for (const Value& a : args->items()) out.proc.args.push_back(a.as_string());
            }
        }
        if (out.proc.pid <= 0) return error("exec: missing pid");
        return ok(std::move(out));
    }
    if (kind == "fork") {
        out.type = EventType::Fork;
        out.proc = es_process(body["child"]);
        const ProcessRef parent = es_process((*doc)["process"]);
        if (out.proc.ppid == 0) out.proc.ppid = parent.pid;
        if (out.proc.path.empty()) out.proc.path = parent.path;
        if (out.proc.pid <= 0) return error("fork: missing child pid");
        return ok(std::move(out));
    }
    if (kind == "exit") {
        out.type = EventType::Exit;
        out.proc = es_process((*doc)["process"]);
        if (out.proc.pid <= 0) return error("exit: missing pid");
        return ok(std::move(out));
    }
    if (kind == "create") {
        out.type = EventType::FileCreate;
        out.proc = es_process((*doc)["process"]);
        out.file_path = es_destination(body);
        if (out.proc.pid <= 0 || out.file_path.empty()) return error("create: missing process or path");
        return ok(std::move(out));
    }
    if (kind == "rename") {
        out.type = EventType::FileRename;
        out.proc = es_process((*doc)["process"]);
        out.file_from = file_path_of(body["source"]);
        out.file_path = es_destination(body);
        if (out.proc.pid <= 0 || out.file_path.empty()) return error("rename: missing process or path");
        return ok(std::move(out));
    }
    if (kind == "close") {
        if (!body["modified"].as_bool()) return skipped();
        out.type = EventType::FileModify;
        out.proc = es_process((*doc)["process"]);
        out.file_path = file_path_of(body["target"]);
        if (out.proc.pid <= 0 || out.file_path.empty()) return error("close: missing process or path");
        return ok(std::move(out));
    }
    return skipped();
}

ParseResult parse_normalized_line(std::string_view line) {
    std::string perr;
    const auto doc = json::parse(line, &perr);
    if (!doc || !doc->is_object()) return error("invalid JSON: " + perr);

    const std::string type = (*doc)["type"].as_string();
    Event ev;
    ev.time_ms = (*doc)["time_ms"].as_int();
    ev.proc = normalized_process(*doc);

    if (type == "exec") {
        ev.type = EventType::Exec;
    } else if (type == "fork") {
        ev.type = EventType::Fork;
    } else if (type == "exit") {
        ev.type = EventType::Exit;
    } else if (type == "file_create" || type == "file_modify" || type == "file_rename") {
        ev.type = type == "file_create" ? EventType::FileCreate
                  : type == "file_modify" ? EventType::FileModify
                                          : EventType::FileRename;
        ev.file_path = (*doc)["file"].as_string();
        ev.file_from = (*doc)["from"].as_string();
        if (ev.file_path.empty()) return error(type + ": missing 'file'");
    } else if (type == "net") {
        ev.type = EventType::NetConnect;
        ev.remote_ip = (*doc)["remote_ip"].as_string();
        ev.remote_port = static_cast<int>((*doc)["remote_port"].as_int());
        ev.remote_host = (*doc)["remote_host"].as_string();
        if (ev.remote_ip.empty()) return error("net: missing 'remote_ip'");
    } else if (type == "dns") {
        ev.type = EventType::DnsQuery;
        ev.dns_name = (*doc)["dns_name"].as_string();
        if (ev.dns_name.empty()) return error("dns: missing 'dns_name'");
    } else {
        return error("unknown type '" + type + "'");
    }
    if (ev.proc.pid <= 0) return error(type + ": missing 'pid'");
    return ok(std::move(ev));
}

ParseResult parse_event_line(std::string_view line) {
    const std::string t = util::trim(line);
    if (t.empty() || t[0] == '#') return skipped();
    // eslogger lines carry an "event" object; normalized lines carry a "type" string.
    if (t.find("\"event\"") != std::string::npos && t.find("\"type\"") == std::string::npos) {
        return parse_eslogger_line(t);
    }
    if (t.find("\"event_type\"") != std::string::npos) return parse_eslogger_line(t);
    return parse_normalized_line(t);
}

}
