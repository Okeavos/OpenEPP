#include "common/util.h"

#include "common/sha256.h"

#include <cctype>
#include <chrono>
#include <ctime>
#include <fstream>

namespace sec::util {

std::string to_lower(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

std::string trim(std::string_view s) {
    std::size_t b = 0;
    std::size_t e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return std::string(s.substr(b, e - b));
}

std::vector<std::string> split(std::string_view s, char delim) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (start <= s.size()) {
        const std::size_t pos = s.find(delim, start);
        if (pos == std::string_view::npos) {
            out.emplace_back(s.substr(start));
            break;
        }
        out.emplace_back(s.substr(start, pos - start));
        start = pos + 1;
    }
    return out;
}

bool read_file(const std::filesystem::path& path, std::vector<std::uint8_t>& out, std::uint64_t max_bytes) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    f.seekg(0, std::ios::end);
    const std::streamoff size = f.tellg();
    if (size < 0) return false;
    if (static_cast<std::uint64_t>(size) > max_bytes) return false;
    f.seekg(0, std::ios::beg);
    out.assign(static_cast<std::size_t>(size), 0);
    if (size > 0) {
        f.read(reinterpret_cast<char*>(out.data()), size);
        if (f.gcount() != size) return false;
    }
    return true;
}

std::optional<std::string> sha256_file(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return std::nullopt;
    Sha256 h;
    std::vector<char> buf(1 << 20);
    while (f) {
        f.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const std::streamsize n = f.gcount();
        if (n > 0) h.update(buf.data(), static_cast<std::size_t>(n));
    }
    if (f.bad()) return std::nullopt;
    return Sha256::to_hex(h.finish());
}

std::string now_iso8601() {
    const std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

std::string path_to_utf8(const std::filesystem::path& p) {
    const auto u8 = p.u8string();
    return std::string(u8.begin(), u8.end());
}

std::filesystem::path path_from_utf8(const std::string& s) {
    return std::filesystem::path(std::u8string(s.begin(), s.end()));
}

bool is_hex(std::string_view s) {
    for (const char c : s) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    return !s.empty();
}

}
