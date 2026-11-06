#include "scanner/hash_db.h"

#include "common/util.h"

#include <fstream>

namespace sec {

bool HashDb::add(const std::string& sha256_hex, const std::string& threat_name) {
    if (sha256_hex.size() != 64 || !util::is_hex(sha256_hex)) return false;
    entries_[util::to_lower(sha256_hex)] = threat_name.empty() ? "Generic.Malware" : threat_name;
    return true;
}

std::size_t HashDb::load_file(const std::filesystem::path& path) {
    std::ifstream f(path);
    if (!f) return 0;
    std::size_t loaded = 0;
    std::string line;
    while (std::getline(f, line)) {
        const std::string t = util::trim(line);
        if (t.empty() || t[0] == '#') continue;
        const std::size_t sp = t.find_first_of(" \t");
        const std::string hash = sp == std::string::npos ? t : t.substr(0, sp);
        const std::string name = sp == std::string::npos ? std::string() : util::trim(t.substr(sp + 1));
        if (add(hash, name)) ++loaded;
    }
    return loaded;
}

const std::string* HashDb::find(const std::string& sha256_hex) const {
    const auto it = entries_.find(util::to_lower(sha256_hex));
    return it == entries_.end() ? nullptr : &it->second;
}

}
