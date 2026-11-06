#pragma once

#include "behavior/engine.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace sec::behavior {

// One alert per line, tab separated, with \\ \t \n escaped. List fields use 0x1f as separator.
std::string alert_to_tsv(const Alert& a);
bool alert_from_tsv(const std::string& line, Alert& out);

// Writer side (used by the sensor daemon). Appends alerts to a file and keeps it from growing forever.
class AlertLog {
public:
    explicit AlertLog(std::filesystem::path file, std::size_t max_keep = 1000);

    bool append(const Alert& a);
    const std::filesystem::path& file() const { return file_; }

private:
    void trim_locked();

    std::filesystem::path file_;
    std::size_t max_keep_;
    std::mutex mutex_;
    std::size_t lines_ = 0;
    bool counted_ = false;
};

// Reader side (used by the menu bar app). Tails the alert file, which another process writes.
class AlertFeed {
public:
    AlertFeed(std::filesystem::path alerts_file, std::filesystem::path seen_file, std::size_t max_recent = 300);

    // Reads whatever was appended since the last call. The first call loads existing history; alerts that
    // are already in the file then count as seen unless the seen-file says otherwise.
    void poll();

    std::vector<Alert> recent() const;  // newest first
    std::size_t total() const;          // alerts read so far (not capped by max_recent)
    std::size_t unseen() const;
    void mark_seen();

private:
    void add_locked(Alert a, const std::string& key);
    void persist_seen_locked() const;

    std::filesystem::path file_;
    std::filesystem::path seen_file_;
    std::size_t max_recent_;
    mutable std::mutex mutex_;
    std::uintmax_t offset_ = 0;
    std::string partial_;
    bool first_poll_ = true;
    std::int64_t seen_ms_ = 0;
    std::size_t total_ = 0;
    std::deque<Alert> recent_;  // oldest first
    std::deque<std::string> keys_;
    std::unordered_set<std::string> key_set_;
};

// Heartbeat written by the sensor daemon, read by the menu bar app.
struct SensorStatus {
    int pid = 0;
    std::int64_t started_ms = 0;
    std::int64_t updated_ms = 0;
    std::string eslogger = "disabled";  // disabled | starting | running | failed
    std::string sockets = "disabled";   // disabled | running | failed
    std::uint64_t events = 0;
    std::uint64_t dropped = 0;
    std::uint64_t alerts = 0;
    std::uint64_t parse_errors = 0;
    std::string last_error;
    std::string rules_error;
};

bool write_status(const std::filesystem::path& file, const SensorStatus& s);
std::optional<SensorStatus> read_status(const std::filesystem::path& file);

// True if the heartbeat is recent enough to consider the daemon alive.
bool status_is_fresh(const SensorStatus& s, std::int64_t now_ms, std::int64_t max_age_ms = 20000);

std::int64_t now_ms();

}
