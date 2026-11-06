// sec-sensord: collects behaviour events (eslogger + TCP socket polling), runs them through the
// behaviour engine and writes alerts for the menu bar app to show. Alert-only; nothing is blocked.
//
// On macOS run it as root (LaunchDaemon, see packaging/macos/install_sensord.sh). The terminal or the
// binary needs Full Disk Access for eslogger to start.
//
//   sec-sensord [--data-dir DIR] [--rules FILE] [--ioc FILE]
//               [--source eslogger|stdin|none] [--eslogger PATH] [--events "exec fork ..."]
//               [--no-sockets] [--poll-ms N] [--console]

#include "agent/agent.h"
#include "behavior/alert_store.h"
#include "behavior/engine.h"
#include "behavior/rules.h"
#include "common/log.h"
#include "common/util.h"
#include "sensor/eslogger_source.h"
#include "sensor/sensor_service.h"
#include "sensor/socket_poller.h"
#include "behavior/es_parser.h"

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <unistd.h>

namespace fs = std::filesystem;
using namespace sec;

namespace {

volatile std::sig_atomic_t g_stop = 0;

void on_signal(int) { g_stop = 1; }

void usage() {
    std::fputs(
        "usage: sec-sensord [--data-dir DIR] [--rules FILE] [--ioc FILE]\n"
        "                   [--source eslogger|stdin|none] [--eslogger PATH] [--events \"exec fork ...\"]\n"
        "                   [--no-sockets] [--poll-ms N] [--console]\n",
        stderr);
}

bool read_text(const fs::path& p, std::string& out) {
    std::ifstream in(p, std::ios::binary);
    if (!in) return false;
    std::ostringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    return true;
}

fs::path default_sensor_dir() {
#if defined(__APPLE__)
    if (::geteuid() == 0) return fs::path("/Library/Application Support/SecEPP");
#endif
    return AgentConfig::default_data_dir();
}

}

int main(int argc, char** argv) {
    fs::path data_dir = default_sensor_dir();
    fs::path rules_file;
    fs::path ioc_file;
    std::string source = "eslogger";
    std::string eslogger_path = "/usr/bin/eslogger";
    std::string events = "exec fork exit create rename close";
    bool sockets = true;
    bool console = false;
    int poll_ms = 1000;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&](std::string& dst) {
            if (i + 1 < argc) dst = argv[++i];
            else {
                usage();
                std::exit(2);
            }
        };
        std::string v;
        if (a == "--data-dir") {
            next(v);
            data_dir = util::path_from_utf8(v);
        } else if (a == "--rules") {
            next(v);
            rules_file = util::path_from_utf8(v);
        } else if (a == "--ioc") {
            next(v);
            ioc_file = util::path_from_utf8(v);
        } else if (a == "--source") {
            next(source);
        } else if (a == "--eslogger") {
            next(eslogger_path);
        } else if (a == "--events") {
            next(events);
        } else if (a == "--poll-ms") {
            next(v);
            poll_ms = std::atoi(v.c_str());
        } else if (a == "--no-sockets") {
            sockets = false;
        } else if (a == "--console") {
            console = true;
        } else {
            usage();
            return 2;
        }
    }
    if (source != "eslogger" && source != "stdin" && source != "none") {
        usage();
        return 2;
    }

    struct sigaction sa;
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    std::signal(SIGPIPE, SIG_IGN);

    std::error_code ec;
    fs::create_directories(data_dir, ec);
    fs::permissions(data_dir, fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec |
                                   fs::perms::others_read | fs::perms::others_exec,
                    fs::perm_options::replace, ec);

    log::set_console(console);
    log::set_level(log::Level::Info);
    log::set_file(data_dir / "logs" / "sensord.log");

    behavior::SensorStatus status;
    status.pid = static_cast<int>(::getpid());
    status.started_ms = behavior::now_ms();

    behavior::RuleSet rules = behavior::default_ruleset();
    if (rules.rules.empty()) {
        std::fputs("built-in rules failed to load\n", stderr);
        return 1;
    }
    if (rules_file.empty() && fs::exists(data_dir / "behavior_rules.json", ec)) rules_file = data_dir / "behavior_rules.json";
    if (!rules_file.empty()) {
        std::string text, err;
        behavior::RuleSet overlay;
        if (!read_text(rules_file, text)) {
            status.rules_error = "cannot read " + util::path_to_utf8(rules_file);
        } else if (!behavior::load_ruleset_text(text, overlay, &err)) {
            status.rules_error = util::path_to_utf8(rules_file) + ": " + err;
        } else {
            behavior::merge_ruleset(rules, overlay);
        }
        if (!status.rules_error.empty()) log::error("rules: " + status.rules_error + " (using built-in rules)");
    }

    behavior::IocSet ioc;
    if (ioc_file.empty() && fs::exists(data_dir / "ioc.json", ec)) ioc_file = data_dir / "ioc.json";
    if (!ioc_file.empty()) {
        std::string text, err;
        if (!read_text(ioc_file, text)) {
            if (status.rules_error.empty()) status.rules_error = "cannot read " + util::path_to_utf8(ioc_file);
        } else if (!behavior::load_ioc_text(text, ioc, &err)) {
            if (status.rules_error.empty()) status.rules_error = util::path_to_utf8(ioc_file) + ": " + err;
        }
    }

    behavior::AlertLog alert_log(data_dir / "behavior_alerts.tsv");
    sensor::SensorService service(std::move(rules), std::move(ioc), &alert_log, [console](const behavior::Alert& a) {
        log::warn("ALERT " + behavior::alert_to_json(a));
        if (console) std::fputs(behavior::alert_to_text(a).c_str(), stdout);
    });
    service.start();

    std::unique_ptr<sensor::EsloggerSource> es;
    if (source == "eslogger") {
        std::vector<std::string> cmd{eslogger_path};
        std::istringstream words(events);
        std::string w;
        while (words >> w) cmd.push_back(w);
        es = std::make_unique<sensor::EsloggerSource>(std::move(cmd), service);
        es->start();
    }

    std::unique_ptr<sensor::SocketPoller> poller;
#if defined(__APPLE__)
    if (sockets && source != "stdin") {
        poller = std::make_unique<sensor::SocketPoller>(&sensor::snapshot_tcp_connections_mac, poll_ms, service);
        poller->start();
    }
#else
    (void)sockets;
    (void)poll_ms;
#endif

    const fs::path status_file = data_dir / "sensor_status.txt";
    auto publish = [&](bool final_write) {
        const sensor::SensorStats st = service.stats();
        status.updated_ms = final_write ? 0 : behavior::now_ms();
        status.events = st.events_processed;
        status.dropped = st.events_dropped;
        status.alerts = st.alerts;
        status.eslogger = "disabled";
        status.last_error.clear();
        status.parse_errors = 0;
        if (es && !final_write) {
            const auto s = es->status();
            status.eslogger = s.state == "stopped" ? "starting" : s.state;
            status.parse_errors = s.parse_errors;
            if (s.state == "failed") status.last_error = s.last_error;
        }
        status.sockets = (poller && !final_write) ? poller->state() : "disabled";
        behavior::write_status(status_file, status);
    };

    log::info("sec-sensord started (data dir " + util::path_to_utf8(data_dir) + ", source " + source + ")");
    publish(false);

    if (source == "stdin") {
        std::string line;
        while (!g_stop && std::getline(std::cin, line)) {
            behavior::ParseResult r = behavior::parse_event_line(line);
            if (r.ok()) service.submit(std::move(r.event));
        }
        service.flush();
    } else {
        int ticks = 0;
        while (!g_stop) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            if (++ticks % 25 == 0) publish(false);
        }
    }

    log::info("sec-sensord stopping");
    if (es) es->stop();
    if (poller) poller->stop();
    service.stop();
    publish(true);
    return 0;
}
