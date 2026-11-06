// Portable foreground agent runner (macOS / Linux / Windows).
// On macOS run it under launchd (see packaging/macos); on Windows prefer sec-service.
//
//   sec-agentd [--config <file>]      Ctrl+C / SIGTERM to stop

#include "agent/agent.h"
#include "common/log.h"
#include "common/util.h"

#include <atomic>
#include <csignal>
#include <cstdio>
#include <string>

namespace {

std::atomic<bool> g_stop{false};

void on_signal(int) { g_stop = true; }

}

int main(int argc, char** argv) {
    std::filesystem::path conf = sec::AgentConfig::default_data_dir() / "sec.conf";
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--config" && i + 1 < argc) {
            conf = sec::util::path_from_utf8(argv[++i]);
        } else {
            std::fputs("usage: sec-agentd [--config <file>]\n", stderr);
            return 2;
        }
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    sec::Config cfg;
    const bool have_cfg = cfg.load(conf);
    const sec::AgentConfig acfg = sec::AgentConfig::from_config(cfg);
    sec::log::set_level(sec::log::parse_level(cfg.get("log_level", "info"), sec::log::Level::Info));
    sec::log::set_file(acfg.data_dir / "logs" / "sec.log");
    if (!have_cfg) sec::log::warn("config not found at " + sec::util::path_to_utf8(conf) + "; using defaults");

    sec::Agent agent(acfg);
    if (!agent.initialize()) return 1;
    sec::log::info("agent started");
    agent.run(g_stop);
    sec::log::info("agent stopped");
    return 0;
}
