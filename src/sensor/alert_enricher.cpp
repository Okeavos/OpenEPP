#include "sensor/alert_enricher.h"

#include "common/util.h"

#include <cstdio>
#include <filesystem>
#include <system_error>

namespace sec::sensor {

namespace {

std::string size_text(std::uint64_t n) {
    char buf[32];
    if (n >= (1ull << 20)) std::snprintf(buf, sizeof(buf), "%.1f MB", static_cast<double>(n) / (1 << 20));
    else if (n >= 1024) std::snprintf(buf, sizeof(buf), "%.1f KB", static_cast<double>(n) / 1024.0);
    else std::snprintf(buf, sizeof(buf), "%llu B", static_cast<unsigned long long>(n));
    return buf;
}

std::string verdict_text(const ScanResult& r) {
    switch (r.verdict) {
        case Verdict::Clean: return "이상 없음 (알려진 악성 시그니처 없음)";
        case Verdict::Suspicious: {
            std::string s = "의심 (점수 " + std::to_string(r.score) + ")";
            if (!r.threat_name.empty()) s += " " + r.threat_name;
            else if (!r.findings.empty()) s += " " + r.findings.front().detail;
            return s;
        }
        case Verdict::Malicious: return "악성: " + (r.threat_name.empty() ? std::string("탐지됨") : r.threat_name);
        case Verdict::Skipped: return "검사 건너뜀" + (r.message.empty() ? std::string() : ": " + r.message);
        case Verdict::Error: return "검사 실패" + (r.message.empty() ? std::string() : ": " + r.message);
    }
    return "알 수 없음";
}

}

std::string AlertEnricher::describe(const ScanResult& r) {
    std::string s = util::path_to_utf8(r.path);
    if (!r.sha256.empty()) s += "  sha256:" + r.sha256 + "  " + size_text(r.size);
    s += "  " + verdict_text(r);
    return s;
}

void AlertEnricher::operator()(behavior::Alert& a) const {
    if (engine_ == nullptr || a.suspect_paths.empty()) return;
    bool malicious = false;
    for (const std::string& p : a.suspect_paths) {
        std::error_code ec;
        if (!std::filesystem::exists(util::path_from_utf8(p), ec)) {
            a.files.push_back(p + "  파일 없음 (이미 삭제되었거나 접근할 수 없음)");
            continue;
        }
        const ScanResult r = engine_->scan_file(util::path_from_utf8(p));
        a.files.push_back(describe(r));
        if (r.verdict == Verdict::Malicious) malicious = true;
    }
    if (malicious) {
        a.level = 2;
        a.title = "[스캐너 악성 판정] " + a.title;
        a.rule_ids.push_back("scanner.malicious");
    }
}

}
