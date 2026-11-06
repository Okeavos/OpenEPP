#include "behavior/alert_store.h"

#include "common/util.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <system_error>

namespace fs = std::filesystem;

namespace sec::behavior {

namespace {

constexpr char kListSep = '\x1f';

std::string escape_field(const std::string& s) {
    std::string o;
    o.reserve(s.size());
    for (const char c : s) {
        switch (c) {
            case '\\': o += "\\\\"; break;
            case '\t': o += "\\t"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case kListSep: break;
            default: o.push_back(c);
        }
    }
    return o;
}

std::string unescape_field(const std::string& s) {
    std::string o;
    o.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '\\' || i + 1 >= s.size()) {
            o.push_back(s[i]);
            continue;
        }
        const char n = s[++i];
        switch (n) {
            case 't': o.push_back('\t'); break;
            case 'n': o.push_back('\n'); break;
            case 'r': o.push_back('\r'); break;
            case '\\': o.push_back('\\'); break;
            default:
                o.push_back('\\');
                o.push_back(n);
        }
    }
    return o;
}

std::string join_list(const std::vector<std::string>& v) {
    std::string o;
    for (std::size_t i = 0; i < v.size(); ++i) {
        if (i != 0) o.push_back(kListSep);
        o += escape_field(v[i]);
    }
    return o;
}

std::vector<std::string> split_list(const std::string& s) {
    std::vector<std::string> out;
    if (s.empty()) return out;
    std::size_t start = 0;
    while (true) {
        const std::size_t pos = s.find(kListSep, start);
        out.push_back(unescape_field(s.substr(start, pos == std::string::npos ? std::string::npos : pos - start)));
        if (pos == std::string::npos) break;
        start = pos + 1;
    }
    return out;
}

bool parse_i64(const std::string& s, std::int64_t& out) {
    if (s.empty() || s.size() > 20) return false;
    std::size_t i = 0;
    bool neg = false;
    if (s[0] == '-') {
        neg = true;
        i = 1;
        if (s.size() == 1) return false;
    }
    std::int64_t v = 0;
    for (; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') return false;
        v = v * 10 + (s[i] - '0');
    }
    out = neg ? -v : v;
    return true;
}

std::vector<std::string> split_tabs(const std::string& line) {
    std::vector<std::string> f;
    std::size_t start = 0;
    while (true) {
        const std::size_t pos = line.find('\t', start);
        f.push_back(line.substr(start, pos == std::string::npos ? std::string::npos : pos - start));
        if (pos == std::string::npos) break;
        start = pos + 1;
    }
    return f;
}

bool write_atomic(const fs::path& file, const std::string& data) {
    std::error_code ec;
    if (file.has_parent_path()) fs::create_directories(file.parent_path(), ec);
    fs::path tmp = file;
    tmp += ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out << data;
        if (!out) return false;
    }
    fs::permissions(tmp,
                    fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read | fs::perms::others_read,
                    fs::perm_options::replace, ec);
    fs::rename(tmp, file, ec);
    return !ec;
}

}

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string alert_to_tsv(const Alert& a) {
    std::string o;
    o += std::to_string(a.time_ms) + "\t";
    o += std::to_string(a.level) + "\t";
    o += std::to_string(a.score) + "\t";
    o += std::to_string(a.pid) + "\t";
    o += escape_field(a.process_path) + "\t";
    o += escape_field(a.title) + "\t";
    o += join_list(a.rule_ids) + "\t";
    o += join_list(a.techniques) + "\t";
    o += join_list(a.chain) + "\t";
    o += escape_field(a.detail);
    return o;
}

bool alert_from_tsv(const std::string& line, Alert& out) {
    const std::vector<std::string> f = split_tabs(line);
    if (f.size() != 10) return false;
    Alert a;
    std::int64_t level = 0, score = 0, pid = 0;
    if (!parse_i64(f[0], a.time_ms) || !parse_i64(f[1], level) || !parse_i64(f[2], score) || !parse_i64(f[3], pid)) {
        return false;
    }
    if (level < 1 || level > 2) return false;
    a.level = static_cast<int>(level);
    a.score = static_cast<int>(score);
    a.pid = static_cast<int>(pid);
    a.process_path = unescape_field(f[4]);
    a.title = unescape_field(f[5]);
    a.rule_ids = split_list(f[6]);
    a.techniques = split_list(f[7]);
    a.chain = split_list(f[8]);
    a.detail = unescape_field(f[9]);
    out = std::move(a);
    return true;
}

// ---- AlertLog ------------------------------------------------------------------------------

AlertLog::AlertLog(fs::path file, std::size_t max_keep)
    : file_(std::move(file)), max_keep_(std::max<std::size_t>(max_keep, 10)) {}

bool AlertLog::append(const Alert& a) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::error_code ec;
    if (file_.has_parent_path()) fs::create_directories(file_.parent_path(), ec);

    if (!counted_) {
        counted_ = true;
        lines_ = 0;
        std::ifstream in(file_, std::ios::binary);
        std::string line;
        while (std::getline(in, line)) ++lines_;
    }

    const bool existed = fs::exists(file_, ec);
    {
        std::ofstream out(file_, std::ios::binary | std::ios::app);
        if (!out) return false;
        out << alert_to_tsv(a) << '\n';
        out.flush();
        if (!out) return false;
    }
    if (!existed) {
        fs::permissions(file_,
                        fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read |
                            fs::perms::others_read,
                        fs::perm_options::replace, ec);
    }
    ++lines_;
    if (lines_ > max_keep_ + 200) trim_locked();
    return true;
}

void AlertLog::trim_locked() {
    std::vector<std::string> lines;
    {
        std::ifstream in(file_, std::ios::binary);
        std::string line;
        while (std::getline(in, line)) {
            if (!line.empty()) lines.push_back(line);
        }
    }
    if (lines.size() > max_keep_) lines.erase(lines.begin(), lines.end() - static_cast<std::ptrdiff_t>(max_keep_));
    std::string data;
    for (const std::string& l : lines) data += l + "\n";
    if (write_atomic(file_, data)) lines_ = lines.size();
}

// ---- AlertFeed -----------------------------------------------------------------------------

AlertFeed::AlertFeed(fs::path alerts_file, fs::path seen_file, std::size_t max_recent)
    : file_(std::move(alerts_file)), seen_file_(std::move(seen_file)), max_recent_(std::max<std::size_t>(max_recent, 10)) {}

void AlertFeed::add_locked(Alert a, const std::string& key) {
    if (key_set_.count(key) != 0) return;
    key_set_.insert(key);
    keys_.push_back(key);
    recent_.push_back(std::move(a));
    ++total_;
    while (recent_.size() > max_recent_) {
        recent_.pop_front();
        key_set_.erase(keys_.front());
        keys_.pop_front();
    }
}

void AlertFeed::persist_seen_locked() const {
    if (seen_file_.empty()) return;
    write_atomic(seen_file_, std::to_string(seen_ms_) + "\n");
}

void AlertFeed::poll() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::error_code ec;
    const std::uintmax_t size = fs::exists(file_, ec) ? fs::file_size(file_, ec) : 0;
    if (ec) return;

    if (size < offset_) {
        offset_ = 0;
        partial_.clear();
    }

    if (size > offset_) {
        std::ifstream in(file_, std::ios::binary);
        if (in) {
            in.seekg(static_cast<std::streamoff>(offset_));
            std::string chunk(static_cast<std::size_t>(size - offset_), '\0');
            in.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
            chunk.resize(static_cast<std::size_t>(in.gcount()));
            offset_ += chunk.size();
            partial_ += chunk;

            std::size_t start = 0;
            while (true) {
                const std::size_t nl = partial_.find('\n', start);
                if (nl == std::string::npos) break;
                const std::string line = partial_.substr(start, nl - start);
                start = nl + 1;
                Alert a;
                if (!line.empty() && alert_from_tsv(line, a)) add_locked(std::move(a), line);
            }
            partial_.erase(0, start);
        }
    }

    if (first_poll_) {
        first_poll_ = false;
        std::int64_t newest = 0;
        for (const Alert& a : recent_) newest = std::max(newest, a.time_ms);

        std::ifstream in(seen_file_);
        std::string text;
        std::int64_t stored = 0;
        if (in && std::getline(in, text) && parse_i64(util::trim(text), stored)) {
            seen_ms_ = stored;
        } else {
            seen_ms_ = newest;
            persist_seen_locked();
        }
    }
}

std::vector<Alert> AlertFeed::recent() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::vector<Alert>(recent_.rbegin(), recent_.rend());
}

std::size_t AlertFeed::total() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return total_;
}

std::size_t AlertFeed::unseen() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::size_t n = 0;
    for (const Alert& a : recent_) {
        if (a.time_ms > seen_ms_) ++n;
    }
    return n;
}

void AlertFeed::mark_seen() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::int64_t newest = seen_ms_;
    for (const Alert& a : recent_) newest = std::max(newest, a.time_ms);
    if (newest == seen_ms_) return;
    seen_ms_ = newest;
    persist_seen_locked();
}

// ---- status --------------------------------------------------------------------------------

bool write_status(const fs::path& file, const SensorStatus& s) {
    std::ostringstream o;
    o << "pid=" << s.pid << "\n";
    o << "started_ms=" << s.started_ms << "\n";
    o << "updated_ms=" << s.updated_ms << "\n";
    o << "eslogger=" << s.eslogger << "\n";
    o << "sockets=" << s.sockets << "\n";
    o << "events=" << s.events << "\n";
    o << "dropped=" << s.dropped << "\n";
    o << "alerts=" << s.alerts << "\n";
    o << "parse_errors=" << s.parse_errors << "\n";
    auto one_line = [](std::string v) {
        std::replace(v.begin(), v.end(), '\n', ' ');
        std::replace(v.begin(), v.end(), '\r', ' ');
        return v;
    };
    o << "last_error=" << one_line(s.last_error) << "\n";
    o << "rules_error=" << one_line(s.rules_error) << "\n";
    return write_atomic(file, o.str());
}

std::optional<SensorStatus> read_status(const fs::path& file) {
    std::ifstream in(file);
    if (!in) return std::nullopt;
    SensorStatus s;
    bool any = false;
    std::string line;
    while (std::getline(in, line)) {
        const std::size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        const std::string k = line.substr(0, eq);
        const std::string v = line.substr(eq + 1);
        std::int64_t n = 0;
        const bool num = parse_i64(v, n);
        any = true;
        if (k == "pid" && num) s.pid = static_cast<int>(n);
        else if (k == "started_ms" && num) s.started_ms = n;
        else if (k == "updated_ms" && num) s.updated_ms = n;
        else if (k == "eslogger") s.eslogger = v;
        else if (k == "sockets") s.sockets = v;
        else if (k == "events" && num) s.events = static_cast<std::uint64_t>(n);
        else if (k == "dropped" && num) s.dropped = static_cast<std::uint64_t>(n);
        else if (k == "alerts" && num) s.alerts = static_cast<std::uint64_t>(n);
        else if (k == "parse_errors" && num) s.parse_errors = static_cast<std::uint64_t>(n);
        else if (k == "last_error") s.last_error = v;
        else if (k == "rules_error") s.rules_error = v;
    }
    if (!any) return std::nullopt;
    return s;
}

bool status_is_fresh(const SensorStatus& s, std::int64_t now, std::int64_t max_age_ms) {
    return s.updated_ms > 0 && now - s.updated_ms <= max_age_ms && now - s.updated_ms >= -max_age_ms;
}

}
