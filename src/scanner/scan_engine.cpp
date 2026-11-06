#include "scanner/scan_engine.h"

#include "common/sha256.h"
#include "common/util.h"
#include "scanner/pe_analyzer.h"

#include <algorithm>
#include <cstring>
#include <functional>
#include <unordered_set>

namespace fs = std::filesystem;

namespace sec {

const char* to_string(Verdict v) {
    switch (v) {
        case Verdict::Clean: return "clean";
        case Verdict::Suspicious: return "suspicious";
        case Verdict::Malicious: return "malicious";
        case Verdict::Skipped: return "skipped";
        case Verdict::Error: return "error";
    }
    return "?";
}

namespace {

// Standard EICAR anti-virus test string (harmless by design).
const char kEicar[] = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

bool contains_bytes(const std::vector<std::uint8_t>& hay, const std::vector<std::uint8_t>& needle) {
    if (needle.empty() || needle.size() > hay.size()) return false;
    const std::uint8_t first = needle[0];
    const std::uint8_t* p = hay.data();
    const std::uint8_t* const last = hay.data() + (hay.size() - needle.size());
    while (p <= last) {
        p = static_cast<const std::uint8_t*>(std::memchr(p, first, static_cast<std::size_t>(last - p) + 1));
        if (p == nullptr) return false;
        if (std::memcmp(p, needle.data(), needle.size()) == 0) return true;
        ++p;
    }
    return false;
}

void add_finding(ScanResult& r, std::string rule, std::string detail, int score) {
    r.findings.push_back({std::move(rule), std::move(detail), score});
    r.score += score;
}

void apply_pe_heuristics(const PeInfo& pe, ScanResult& r) {
    static const char* const kPackerSections[] = {"upx0", "upx1", "upx2", ".aspack", ".adata", ".themida",
                                                  ".vmp0", ".vmp1", ".petite", ".mpress1", ".mpress2"};
    bool packer_flagged = false;
    bool entropy_flagged = false;
    bool wx_flagged = false;

    for (const PeSection& s : pe.sections) {
        const std::string lname = util::to_lower(s.name);
        if (!packer_flagged) {
            for (const char* p : kPackerSections) {
                if (lname == p) {
                    add_finding(r, "pe.packer_section", "known packer section name: " + s.name, 20);
                    packer_flagged = true;
                    break;
                }
            }
        }
        if (!entropy_flagged && s.executable() && s.raw_size >= 1024 && s.entropy > 7.2) {
            add_finding(r, "pe.high_entropy_code", "executable section " + s.name + " looks packed/encrypted", 25);
            entropy_flagged = true;
        }
        if (!wx_flagged && s.executable() && s.writable()) {
            add_finding(r, "pe.wx_section", "section " + s.name + " is writable and executable", 15);
            wx_flagged = true;
        }
    }

    std::unordered_set<std::string> fn;
    for (const std::string& name : pe.imported_functions) fn.insert(util::to_lower(name));
    auto has = [&](const char* n) { return fn.count(n) > 0; };

    if (has("virtualallocex") && has("writeprocessmemory") &&
        (has("createremotethread") || has("ntcreatethreadex") || has("queueuserapc"))) {
        add_finding(r, "pe.process_injection_imports", "VirtualAllocEx + WriteProcessMemory + remote thread APIs", 40);
    }
    if ((has("setwindowshookexa") || has("setwindowshookexw")) &&
        (has("getasynckeystate") || has("getkeystate") || has("getkeyboardstate"))) {
        add_finding(r, "pe.keylogger_imports", "keyboard hook combined with key state polling", 15);
    }
    if ((has("urldownloadtofilea") || has("urldownloadtofilew")) &&
        (has("winexec") || has("shellexecutea") || has("shellexecutew") || has("createprocessa") ||
         has("createprocessw"))) {
        add_finding(r, "pe.downloader_imports", "download-to-file combined with process execution", 20);
    }
    if (has("isdebuggerpresent") || has("checkremotedebuggerpresent")) {
        add_finding(r, "pe.anti_debug_imports", "anti-debugging API imported", 5);
    }
    if (pe.imported_functions.size() <= 5 && (has("loadlibrarya") || has("loadlibraryw")) && has("getprocaddress")) {
        add_finding(r, "pe.dynamic_resolution_only", "almost no static imports; resolves APIs at runtime", 15);
    }
}

}

ScanEngine::ScanEngine() {
    PatternRule eicar;
    eicar.name = "EICAR-Test-File";
    eicar.bytes.assign(reinterpret_cast<const std::uint8_t*>(kEicar),
                       reinterpret_cast<const std::uint8_t*>(kEicar) + sizeof(kEicar) - 1);
    patterns_.push_back(std::move(eicar));
}

void ScanEngine::add_pattern(PatternRule rule) {
    if (!rule.bytes.empty()) patterns_.push_back(std::move(rule));
}

ScanResult ScanEngine::scan_file(const fs::path& path) const {
    ScanResult r;
    r.path = path;

    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) {
        r.verdict = Verdict::Skipped;
        r.message = "not a regular file";
        return r;
    }
    r.size = fs::file_size(path, ec);
    if (ec) {
        r.verdict = Verdict::Error;
        r.message = "cannot stat file: " + ec.message();
        return r;
    }
    if (r.size > options_.max_file_size) {
        r.verdict = Verdict::Skipped;
        r.message = "file exceeds max_file_size";
        return r;
    }

    std::vector<std::uint8_t> data;
    const bool analyze = r.size <= options_.max_analyze_size;
    if (analyze) {
        if (!util::read_file(path, data, options_.max_analyze_size)) {
            r.verdict = Verdict::Error;
            r.message = "cannot read file";
            return r;
        }
        r.sha256 = Sha256::to_hex(Sha256::of(data.data(), data.size()));
    } else {
        const auto sha = util::sha256_file(path);
        if (!sha) {
            r.verdict = Verdict::Error;
            r.message = "cannot read file";
            return r;
        }
        r.sha256 = *sha;
    }

    // 1) Known-bad hash.
    if (const std::string* name = hash_db_.find(r.sha256)) {
        add_finding(r, "hash.known_bad", "SHA-256 matches known malware: " + *name, 100);
        r.threat_name = *name;
    }

    if (analyze && !data.empty()) {
        // 2) Byte-pattern signatures.
        for (const PatternRule& p : patterns_) {
            if (contains_bytes(data, p.bytes)) {
                add_finding(r, "pattern.match", "signature match: " + p.name, 100);
                if (r.threat_name.empty()) r.threat_name = p.name;
            }
        }

        // 3) Static PE heuristics.
        if (const auto pe = analyze_pe(data.data(), data.size())) apply_pe_heuristics(*pe, r);
    }

    r.score = std::min(r.score, 100);
    if (r.score >= options_.malicious_threshold) {
        r.verdict = Verdict::Malicious;
        if (r.threat_name.empty()) r.threat_name = "Heuristic.Generic";
    } else if (r.score >= options_.suspicious_threshold) {
        r.verdict = Verdict::Suspicious;
    } else {
        r.verdict = Verdict::Clean;
    }
    return r;
}

ScanSummary ScanEngine::scan_path(const fs::path& root, const std::function<void(const ScanResult&)>& on_result,
                                  const std::atomic<bool>* cancel) const {
    ScanSummary sum;
    auto handle = [&](const ScanResult& r) {
        switch (r.verdict) {
            case Verdict::Clean: ++sum.clean; break;
            case Verdict::Suspicious: ++sum.suspicious; break;
            case Verdict::Malicious: ++sum.malicious; break;
            case Verdict::Skipped: ++sum.skipped; break;
            case Verdict::Error: ++sum.errors; break;
        }
        if (r.verdict != Verdict::Skipped && r.verdict != Verdict::Error) ++sum.scanned;
        if (on_result) on_result(r);
    };
    auto cancelled = [&] { return cancel != nullptr && cancel->load(); };

    std::error_code ec;
    if (fs::is_regular_file(root, ec)) {
        handle(scan_file(root));
        return sum;
    }

    fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec);
    if (ec) {
        ++sum.errors;
        return sum;
    }
    for (const fs::recursive_directory_iterator end; it != end; it.increment(ec)) {
        if (cancelled()) {
            sum.cancelled = true;
            break;
        }
        if (ec) {
            ++sum.errors;
            ec.clear();
            continue;
        }
        std::error_code type_ec;
        if (it->is_symlink(type_ec) || !it->is_regular_file(type_ec)) continue;
        handle(scan_file(it->path()));
    }
    return sum;
}

}
