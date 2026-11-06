#include "agent/agent.h"

#include "common/log.h"
#include "common/util.h"

#include <chrono>
#include <cstdlib>
#include <string>
#include <thread>

namespace fs = std::filesystem;

namespace sec {

namespace {

fs::path home_dir() {
#ifdef _WIN32
    if (const char* h = std::getenv("USERPROFILE")) return fs::path(h);
#else
    if (const char* h = std::getenv("HOME")) return fs::path(h);
#endif
    return fs::path();
}

fs::path expand_home(const std::string& s) {
    if (s == "~") return home_dir();
    if (s.size() >= 2 && s[0] == '~' && (s[1] == '/' || s[1] == '\\')) {
        const fs::path h = home_dir();
        if (!h.empty()) return h / util::path_from_utf8(s.substr(2));
    }
    return util::path_from_utf8(s);
}

std::vector<fs::path> parse_path_list(const std::string& value) {
    std::vector<fs::path> out;
    for (const std::string& p : util::split(value, ';')) {
        const std::string t = util::trim(p);
        if (!t.empty()) out.push_back(expand_home(t));
    }
    return out;
}

}

fs::path AgentConfig::default_data_dir() {
#ifdef _WIN32
    if (const char* pd = std::getenv("ProgramData")) return fs::path(pd) / "SecEPP";
    return fs::path("C:\\ProgramData\\SecEPP");
#elif defined(__APPLE__)
    if (const char* home = std::getenv("HOME")) return fs::path(home) / "Library" / "Application Support" / "SecEPP";
    return fs::path("./sec-data");
#else
    return fs::path("./sec-data");
#endif
}

std::vector<fs::path> AgentConfig::default_watch_paths() {
    const fs::path h = home_dir();
    if (h.empty()) return {};
    return {h / "Downloads", h / "Desktop", h / "Documents"};
}

AgentConfig AgentConfig::from_config(const Config& cfg) {
    AgentConfig a;
    const std::string dd = cfg.get("data_dir");
    a.data_dir = dd.empty() ? default_data_dir() : expand_home(dd);

    const std::string hp = cfg.get("hash_db");
    a.hash_db_path = hp.empty() ? a.data_dir / "hashes.txt" : expand_home(hp);

    a.scan_paths = parse_path_list(cfg.get("scan_paths"));
    a.watch_paths = parse_path_list(cfg.get("watch_paths"));
    if (a.watch_paths.empty()) a.watch_paths = default_watch_paths();
    a.realtime_enabled = cfg.get_bool("realtime", true);

    a.auto_quarantine = cfg.get_bool("auto_quarantine", false);
    a.scan_interval_minutes = static_cast<int>(cfg.get_int("scan_interval_minutes", 0));

    const std::int64_t max_mb = cfg.get_int("max_file_size_mb", 512);
    if (max_mb > 0) a.scan_options.max_file_size = static_cast<std::uint64_t>(max_mb) << 20;
    a.scan_options.suspicious_threshold = static_cast<int>(cfg.get_int("suspicious_threshold", 40));
    a.scan_options.malicious_threshold = static_cast<int>(cfg.get_int("malicious_threshold", 90));
    return a;
}

Agent::Agent(AgentConfig cfg) : cfg_(std::move(cfg)) {}

bool Agent::initialize() {
    std::error_code ec;
    fs::create_directories(cfg_.data_dir, ec);
    if (ec) {
        log::error("cannot create data dir " + util::path_to_utf8(cfg_.data_dir) + ": " + ec.message());
        return false;
    }
    quarantine_ = std::make_unique<Quarantine>(cfg_.data_dir / "quarantine");
    engine_.set_options(cfg_.scan_options);

    const std::size_t n = engine_.hash_db().load_file(cfg_.hash_db_path);
    log::info("hash db: " + std::to_string(n) + " entries from " + util::path_to_utf8(cfg_.hash_db_path));
    return true;
}

std::string Agent::handle_detection(const ScanResult& r) {
    log::warn(std::string(to_string(r.verdict)) + ": " + util::path_to_utf8(r.path) + " (score " +
              std::to_string(r.score) + ", " + r.threat_name + ", sha256 " + r.sha256 + ")");

    std::string action = "none";
    if (r.verdict == Verdict::Malicious && cfg_.auto_quarantine && quarantine_) {
        QuarantineEntry entry;
        std::string err;
        if (quarantine_->quarantine_file(r.path, r.threat_name, entry, err)) {
            action = "quarantined";
            log::info("quarantined " + util::path_to_utf8(r.path) + " as " + entry.id);
        } else {
            action = "quarantine_failed";
            log::error("quarantine failed for " + util::path_to_utf8(r.path) + ": " + err);
        }
    }

    if (store_ != nullptr) {
        DetectionRecord rec;
        rec.time = util::now_iso8601();
        rec.path = util::path_to_utf8(r.path);
        rec.verdict = to_string(r.verdict);
        rec.threat = !r.threat_name.empty() ? r.threat_name
                                            : (!r.findings.empty() ? r.findings.front().rule : "Heuristic.Suspicious");
        rec.score = r.score;
        rec.sha256 = r.sha256;
        rec.action = action;
        store_->add(std::move(rec));
    }
    return action;
}

ScanSummary Agent::scan_now(const std::atomic<bool>* cancel) {
    ScanSummary total;
    for (const fs::path& root : cfg_.scan_paths) {
        log::info("scan start: " + util::path_to_utf8(root));
        const ScanSummary s = engine_.scan_path(
            root,
            [this](const ScanResult& r) {
                if (r.verdict == Verdict::Malicious || r.verdict == Verdict::Suspicious) handle_detection(r);
            },
            cancel);
        total.scanned += s.scanned;
        total.clean += s.clean;
        total.suspicious += s.suspicious;
        total.malicious += s.malicious;
        total.skipped += s.skipped;
        total.errors += s.errors;
        if (s.cancelled) {
            total.cancelled = true;
            break;
        }
    }
    log::info("scan done: scanned=" + std::to_string(total.scanned) + " malicious=" + std::to_string(total.malicious) +
              " suspicious=" + std::to_string(total.suspicious) + " skipped=" + std::to_string(total.skipped) +
              " errors=" + std::to_string(total.errors));
    return total;
}

void Agent::run(const std::atomic<bool>& stop) {
    using namespace std::chrono;
    while (!stop.load()) {
        scan_now(&stop);
        if (cfg_.scan_interval_minutes <= 0) {
            while (!stop.load()) std::this_thread::sleep_for(milliseconds(250));
            return;
        }
        const auto deadline = steady_clock::now() + minutes(cfg_.scan_interval_minutes);
        while (!stop.load() && steady_clock::now() < deadline) std::this_thread::sleep_for(milliseconds(250));
    }
}

}
