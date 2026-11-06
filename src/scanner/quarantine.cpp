#include "scanner/quarantine.h"

#include "common/sha256.h"
#include "common/util.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <random>

namespace fs = std::filesystem;

namespace sec {

namespace {

constexpr char kMagic[8] = {'S', 'E', 'C', 'Q', '1', 0, 0, 0};
constexpr std::uint8_t kXorKey = 0xA5;
constexpr std::size_t kChunk = 1 << 20;

bool valid_id(const std::string& id) {
    if (id.empty() || id.size() > 64) return false;
    return std::all_of(id.begin(), id.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == '-';
    });
}

std::string one_line(std::string s) {
    for (char& c : s) {
        if (c == '\n' || c == '\r') c = ' ';
    }
    return s;
}

std::string random_hex8() {
    std::random_device rd;
    const std::uint32_t v = rd();
    static const char kHex[] = "0123456789abcdef";
    std::string s(8, '0');
    for (int i = 0; i < 8; ++i) s[7 - i] = kHex[(v >> (i * 4)) & 0xf];
    return s;
}

void xor_buffer(char* buf, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) buf[i] = static_cast<char>(static_cast<std::uint8_t>(buf[i]) ^ kXorKey);
}

}

fs::path Quarantine::payload_path(const std::string& id) const { return dir_ / (id + ".qf"); }
fs::path Quarantine::meta_path(const std::string& id) const { return dir_ / (id + ".meta"); }

bool Quarantine::quarantine_file(const fs::path& file, const std::string& threat, QuarantineEntry& out,
                                 std::string& error) {
    std::error_code ec;
    fs::create_directories(dir_, ec);
    if (ec) {
        error = "cannot create quarantine directory: " + ec.message();
        return false;
    }

    const auto sha = util::sha256_file(file);
    if (!sha) {
        error = "cannot read file";
        return false;
    }
    const std::uint64_t size = fs::file_size(file, ec);
    if (ec) {
        error = "cannot stat file: " + ec.message();
        return false;
    }

    QuarantineEntry e;
    e.id = sha->substr(0, 16) + "-" + random_hex8();
    e.original_path = util::path_to_utf8(fs::absolute(file, ec));
    e.sha256 = *sha;
    e.threat = threat;
    e.time = util::now_iso8601();
    e.size = size;

    {
        std::ifstream in(file, std::ios::binary);
        std::ofstream o(payload_path(e.id), std::ios::binary | std::ios::trunc);
        if (!in || !o) {
            error = "cannot open source or quarantine payload";
            return false;
        }
        o.write(kMagic, sizeof(kMagic));
        std::vector<char> buf(kChunk);
        while (in) {
            in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
            const std::streamsize n = in.gcount();
            if (n <= 0) break;
            xor_buffer(buf.data(), static_cast<std::size_t>(n));
            o.write(buf.data(), n);
        }
        o.flush();
        if (!o) {
            o.close();
            fs::remove(payload_path(e.id), ec);
            error = "write to quarantine failed";
            return false;
        }
    }

    {
        std::ofstream m(meta_path(e.id), std::ios::trunc);
        m << "id=" << e.id << '\n'
          << "original_path=" << one_line(e.original_path) << '\n'
          << "sha256=" << e.sha256 << '\n'
          << "threat=" << one_line(e.threat) << '\n'
          << "time=" << e.time << '\n'
          << "size=" << e.size << '\n';
        m.flush();
        if (!m) {
            m.close();
            fs::remove(payload_path(e.id), ec);
            fs::remove(meta_path(e.id), ec);
            error = "cannot write quarantine metadata";
            return false;
        }
    }

    fs::remove(file, ec);
    if (ec) {
        // Never leave a copy in quarantine while the live file stays: roll back.
        std::error_code ignore;
        fs::remove(payload_path(e.id), ignore);
        fs::remove(meta_path(e.id), ignore);
        error = "could not delete original file: " + ec.message();
        return false;
    }

    out = std::move(e);
    return true;
}

bool Quarantine::load_entry(const std::string& id, QuarantineEntry& out) const {
    if (!valid_id(id)) return false;
    std::ifstream m(meta_path(id));
    if (!m) return false;
    QuarantineEntry e;
    std::string line;
    while (std::getline(m, line)) {
        const std::size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        const std::string k = line.substr(0, eq);
        const std::string v = line.substr(eq + 1);
        if (k == "id") e.id = v;
        else if (k == "original_path") e.original_path = v;
        else if (k == "sha256") e.sha256 = v;
        else if (k == "threat") e.threat = v;
        else if (k == "time") e.time = v;
        else if (k == "size") {
            try {
                e.size = std::stoull(v);
            } catch (...) {
                e.size = 0;
            }
        }
    }
    if (e.id != id) return false;
    out = std::move(e);
    return true;
}

std::vector<QuarantineEntry> Quarantine::list() const {
    std::vector<QuarantineEntry> out;
    std::error_code ec;
    if (!fs::is_directory(dir_, ec)) return out;
    for (fs::directory_iterator it(dir_, ec), end; !ec && it != end; it.increment(ec)) {
        if (it->path().extension() != ".meta") continue;
        QuarantineEntry e;
        if (load_entry(it->path().stem().string(), e)) out.push_back(std::move(e));
    }
    std::sort(out.begin(), out.end(), [](const QuarantineEntry& a, const QuarantineEntry& b) { return a.time < b.time; });
    return out;
}

bool Quarantine::restore(const std::string& id, const fs::path& dest, bool overwrite, std::string& error) {
    QuarantineEntry e;
    if (!load_entry(id, e)) {
        error = "unknown quarantine id";
        return false;
    }
    const fs::path target = dest.empty() ? util::path_from_utf8(e.original_path) : dest;
    std::error_code ec;
    if (!overwrite && fs::exists(target, ec)) {
        error = "destination already exists";
        return false;
    }
    if (target.has_parent_path()) fs::create_directories(target.parent_path(), ec);

    std::ifstream in(payload_path(id), std::ios::binary);
    if (!in) {
        error = "quarantine payload missing";
        return false;
    }
    char magic[sizeof(kMagic)] = {};
    in.read(magic, sizeof(magic));
    if (in.gcount() != static_cast<std::streamsize>(sizeof(magic)) || std::memcmp(magic, kMagic, sizeof(magic)) != 0) {
        error = "corrupt quarantine payload (bad header)";
        return false;
    }

    Sha256 hasher;
    {
        std::ofstream o(target, std::ios::binary | std::ios::trunc);
        if (!o) {
            error = "cannot create destination file";
            return false;
        }
        std::vector<char> buf(kChunk);
        while (in) {
            in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
            const std::streamsize n = in.gcount();
            if (n <= 0) break;
            xor_buffer(buf.data(), static_cast<std::size_t>(n));
            hasher.update(buf.data(), static_cast<std::size_t>(n));
            o.write(buf.data(), n);
        }
        o.flush();
        if (!o) {
            o.close();
            fs::remove(target, ec);
            error = "write to destination failed";
            return false;
        }
    }

    if (Sha256::to_hex(hasher.finish()) != e.sha256) {
        fs::remove(target, ec);
        error = "integrity check failed (SHA-256 mismatch); restored file discarded";
        return false;
    }

    fs::remove(payload_path(id), ec);
    fs::remove(meta_path(id), ec);
    return true;
}

bool Quarantine::remove(const std::string& id, std::string& error) {
    QuarantineEntry e;
    if (!load_entry(id, e)) {
        error = "unknown quarantine id";
        return false;
    }
    std::error_code ec;
    fs::remove(payload_path(id), ec);
    fs::remove(meta_path(id), ec);
    return true;
}

}
