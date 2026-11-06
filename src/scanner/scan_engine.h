#pragma once

#include "scanner/hash_db.h"

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace sec {

enum class Verdict { Clean, Suspicious, Malicious, Skipped, Error };

const char* to_string(Verdict v);

struct Finding {
    std::string rule;    // machine-readable rule id, e.g. "pe.wx_section"
    std::string detail;  // human-readable
    int score = 0;       // contribution to the heuristic score (100 = definitive)
};

struct ScanResult {
    std::filesystem::path path;
    Verdict verdict = Verdict::Clean;
    int score = 0;  // 0..100
    std::uint64_t size = 0;
    std::string sha256;
    std::string threat_name;
    std::vector<Finding> findings;
    std::string message;  // reason for Skipped / Error
};

struct ScanOptions {
    std::uint64_t max_file_size = 512ull << 20;    // larger files are skipped
    std::uint64_t max_analyze_size = 64ull << 20;  // larger files are hashed only (no content analysis)
    int suspicious_threshold = 40;
    int malicious_threshold = 90;
};

struct ScanSummary {
    std::uint64_t scanned = 0;
    std::uint64_t clean = 0;
    std::uint64_t suspicious = 0;
    std::uint64_t malicious = 0;
    std::uint64_t skipped = 0;
    std::uint64_t errors = 0;
    bool cancelled = false;
};

// A byte-pattern signature (exact match anywhere in the file).
struct PatternRule {
    std::string name;
    std::vector<std::uint8_t> bytes;
};

class ScanEngine {
public:
    ScanEngine();  // registers the built-in EICAR test signature

    void set_options(const ScanOptions& o) { options_ = o; }
    const ScanOptions& options() const { return options_; }

    HashDb& hash_db() { return hash_db_; }
    const HashDb& hash_db() const { return hash_db_; }

    void add_pattern(PatternRule rule);

    ScanResult scan_file(const std::filesystem::path& path) const;

    // Scans a file or walks a directory tree (symlinks are not followed).
    // on_result is called for every scanned file. Set *cancel to stop early.
    ScanSummary scan_path(const std::filesystem::path& root, const std::function<void(const ScanResult&)>& on_result,
                          const std::atomic<bool>* cancel = nullptr) const;

private:
    ScanOptions options_;
    HashDb hash_db_;
    std::vector<PatternRule> patterns_;
};

}
