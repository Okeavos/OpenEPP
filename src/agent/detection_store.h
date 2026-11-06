#pragma once

#include <cstddef>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

namespace sec {

struct DetectionRecord {
    std::string time;     // UTC ISO-8601
    std::string path;     // UTF-8
    std::string verdict;  // "malicious" | "suspicious"
    std::string threat;
    int score = 0;
    std::string sha256;
    std::string action;  // "none" | "quarantined" | "quarantine_failed"
};

// Thread-safe detection history. Persisted as a tab-separated file; the newest
// `max_in_memory` records are kept in memory for the UI.
class DetectionStore {
public:
    explicit DetectionStore(std::filesystem::path file, std::size_t max_in_memory = 500);

    // Reads the existing history. Everything loaded counts as already seen.
    void load();

    void add(DetectionRecord record);

    // Newest first.
    std::vector<DetectionRecord> recent() const;

    std::size_t total() const;
    // Detections added since the last mark_seen() (drives the red alert icon).
    std::size_t unseen() const;
    void mark_seen();

private:
    std::filesystem::path file_;
    std::size_t max_;
    mutable std::mutex mutex_;
    std::vector<DetectionRecord> records_;
    std::size_t total_ = 0;
    std::size_t seen_ = 0;
};

}
