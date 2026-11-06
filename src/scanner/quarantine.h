#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace sec {

struct QuarantineEntry {
    std::string id;
    std::string original_path;  // UTF-8
    std::string sha256;
    std::string threat;
    std::string time;
    std::uint64_t size = 0;
};

// Moves files into a quarantine directory as "<id>.qf" (+ "<id>.meta").
//
// NOTE: the payload is only XOR-obfuscated (so it cannot be executed or re-detected in place).
// It is NOT encryption. Replacing it with authenticated encryption (AES-GCM via CNG) is a TODO
// before this is used on real endpoints.
class Quarantine {
public:
    explicit Quarantine(std::filesystem::path dir) : dir_(std::move(dir)) {}

    bool quarantine_file(const std::filesystem::path& file, const std::string& threat, QuarantineEntry& out,
                         std::string& error);

    // Restores to dest (or the original path if dest is empty). Verifies the SHA-256 after restoring.
    bool restore(const std::string& id, const std::filesystem::path& dest, bool overwrite, std::string& error);

    bool remove(const std::string& id, std::string& error);

    std::vector<QuarantineEntry> list() const;

    const std::filesystem::path& directory() const { return dir_; }

private:
    bool load_entry(const std::string& id, QuarantineEntry& out) const;
    std::filesystem::path payload_path(const std::string& id) const;
    std::filesystem::path meta_path(const std::string& id) const;

    std::filesystem::path dir_;
};

}
