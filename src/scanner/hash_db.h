#pragma once

#include <cstddef>
#include <filesystem>
#include <string>
#include <unordered_map>

namespace sec {

// Known-bad SHA-256 database.
// File format: one entry per line, "<64 hex chars> [threat name]". '#' starts a comment.
class HashDb {
public:
    // Returns the number of entries loaded from the file (0 if unreadable).
    std::size_t load_file(const std::filesystem::path& path);

    // Returns false if sha256_hex is not a valid 64-char hex string.
    bool add(const std::string& sha256_hex, const std::string& threat_name);

    // Returns the threat name or nullptr when the hash is unknown.
    const std::string* find(const std::string& sha256_hex) const;

    std::size_t size() const { return entries_.size(); }

private:
    std::unordered_map<std::string, std::string> entries_;
};

}
