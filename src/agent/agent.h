#pragma once

#include "agent/detection_store.h"
#include "common/config.h"
#include "scanner/quarantine.h"
#include "scanner/scan_engine.h"

#include <atomic>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace sec {

struct AgentConfig {
    std::filesystem::path data_dir;
    std::filesystem::path hash_db_path;  // default: <data_dir>/hashes.txt
    std::vector<std::filesystem::path> scan_paths;
    std::vector<std::filesystem::path> watch_paths;  // real-time monitoring roots
    bool realtime_enabled = true;
    bool auto_quarantine = false;
    int scan_interval_minutes = 0;  // 0 = scan once, then idle until stopped
    ScanOptions scan_options;

    static std::filesystem::path default_data_dir();
    // Downloads, Desktop, Documents of the current user.
    static std::vector<std::filesystem::path> default_watch_paths();
    static AgentConfig from_config(const Config& cfg);
};

// Platform-neutral agent core: owns the engine + quarantine and runs (scheduled) scans.
// The Windows service host, the console runner and the macOS menu bar app all drive this class.
class Agent {
public:
    explicit Agent(AgentConfig cfg);

    // Loads the hash DB and prepares directories. Safe to call once before run()/scan_now().
    bool initialize();

    ScanSummary scan_now(const std::atomic<bool>* cancel = nullptr);

    // Blocks until stop becomes true.
    void run(const std::atomic<bool>& stop);

    // Optional: every malicious/suspicious result is recorded here.
    void set_detection_store(DetectionStore* store) { store_ = store; }

    // Logs, auto-quarantines (if enabled and malicious) and records a detection.
    // Returns the action taken: "none" | "quarantined" | "quarantine_failed". Thread-safe.
    std::string handle_detection(const ScanResult& r);

    ScanEngine& engine() { return engine_; }
    Quarantine& quarantine() { return *quarantine_; }
    const AgentConfig& config() const { return cfg_; }

private:
    AgentConfig cfg_;
    ScanEngine engine_;
    std::unique_ptr<Quarantine> quarantine_;
    DetectionStore* store_ = nullptr;
};

}
