#include "common/config.h"

#include "common/util.h"

#include <charconv>
#include <fstream>

namespace sec {

bool Config::load(const std::filesystem::path& path) {
    std::ifstream f(path);
    if (!f) return false;
    std::string line;
    bool first = true;
    while (std::getline(f, line)) {
        if (first) {
            first = false;
            if (line.size() >= 3 && static_cast<unsigned char>(line[0]) == 0xEF &&
                static_cast<unsigned char>(line[1]) == 0xBB && static_cast<unsigned char>(line[2]) == 0xBF) {
                line.erase(0, 3);  // UTF-8 BOM
            }
        }
        const std::string t = util::trim(line);
        if (t.empty() || t[0] == '#' || t[0] == ';') continue;
        const std::size_t eq = t.find('=');
        if (eq == std::string::npos) continue;
        const std::string key = util::to_lower(util::trim(t.substr(0, eq)));
        const std::string value = util::trim(t.substr(eq + 1));
        if (!key.empty()) values_[key] = value;
    }
    return true;
}

std::string Config::get(const std::string& key, const std::string& fallback) const {
    const auto it = values_.find(util::to_lower(key));
    return it == values_.end() ? fallback : it->second;
}

std::int64_t Config::get_int(const std::string& key, std::int64_t fallback) const {
    const auto it = values_.find(util::to_lower(key));
    if (it == values_.end()) return fallback;
    std::int64_t v = 0;
    const std::string& s = it->second;
    const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc() || ptr != s.data() + s.size()) return fallback;
    return v;
}

bool Config::get_bool(const std::string& key, bool fallback) const {
    const auto it = values_.find(util::to_lower(key));
    if (it == values_.end()) return fallback;
    const std::string v = util::to_lower(it->second);
    if (v == "1" || v == "true" || v == "yes" || v == "on") return true;
    if (v == "0" || v == "false" || v == "no" || v == "off") return false;
    return fallback;
}

void Config::set(const std::string& key, const std::string& value) {
    values_[util::to_lower(key)] = value;
}

bool Config::has(const std::string& key) const {
    return values_.count(util::to_lower(key)) > 0;
}

}
