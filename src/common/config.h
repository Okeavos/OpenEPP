#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <unordered_map>

namespace sec {

// Minimal "key = value" configuration file. '#' and ';' start comments.
class Config {
public:
    bool load(const std::filesystem::path& path);

    std::string get(const std::string& key, const std::string& fallback = {}) const;
    std::int64_t get_int(const std::string& key, std::int64_t fallback) const;
    bool get_bool(const std::string& key, bool fallback) const;
    void set(const std::string& key, const std::string& value);
    bool has(const std::string& key) const;

private:
    std::unordered_map<std::string, std::string> values_;
};

}
