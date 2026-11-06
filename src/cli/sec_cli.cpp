#include "agent/agent.h"
#include "cli/behavior_cmd.h"
#include "common/log.h"
#include "common/sha256.h"
#include "common/util.h"
#include "scanner/pe_analyzer.h"

#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace sec;

namespace {

void usage() {
    std::puts(
        "sec-cli - Sec EPP command line\n"
        "\n"
        "  sec-cli scan <path> [--hashdb <file>] [--quarantine] [--data-dir <dir>] [--all]\n"
        "      Scan a file or directory. --all also prints clean files.\n"
        "  sec-cli hash <file>\n"
        "      Print the SHA-256 of a file.\n"
        "  sec-cli pe <file>\n"
        "      Dump static PE information.\n"
        "  sec-cli quarantine list|restore <id>|delete <id> [--data-dir <dir>] [--to <path>]\n"
        "  sec-cli behavior-replay <events.jsonl|-> [--rules <file>] [--ioc <file>] [--json]\n"
        "      Replay recorded sensor events (eslogger or normalized JSONL) through the behaviour engine.\n"
        "  sec-cli behavior-rules\n"
        "      Print the built-in behaviour rules as JSON.\n");
}

struct Args {
    std::vector<std::string> positional;
    std::string hashdb;
    std::string data_dir;
    std::string to;
    bool quarantine = false;
    bool all = false;
};

Args parse(int argc, char** argv, int from) {
    Args a;
    for (int i = from; i < argc; ++i) {
        const std::string s = argv[i];
        auto next = [&](std::string& dst) {
            if (i + 1 < argc) dst = argv[++i];
        };
        if (s == "--hashdb") next(a.hashdb);
        else if (s == "--data-dir") next(a.data_dir);
        else if (s == "--to") next(a.to);
        else if (s == "--quarantine") a.quarantine = true;
        else if (s == "--all") a.all = true;
        else a.positional.push_back(s);
    }
    return a;
}

fs::path data_dir_of(const Args& a) {
    return a.data_dir.empty() ? AgentConfig::default_data_dir() : util::path_from_utf8(a.data_dir);
}

int cmd_scan(const Args& a) {
    if (a.positional.empty()) {
        usage();
        return 2;
    }
    AgentConfig cfg;
    cfg.data_dir = data_dir_of(a);
    cfg.hash_db_path = a.hashdb.empty() ? cfg.data_dir / "hashes.txt" : util::path_from_utf8(a.hashdb);
    cfg.scan_paths.push_back(util::path_from_utf8(a.positional[0]));
    cfg.auto_quarantine = a.quarantine;

    Agent agent(cfg);
    if (!agent.initialize()) return 3;

    const ScanSummary sum = agent.engine().scan_path(cfg.scan_paths[0], [&](const ScanResult& r) {
        if (r.verdict == Verdict::Clean && !a.all) return;
        std::printf("[%s] %s  score=%d", to_string(r.verdict), util::path_to_utf8(r.path).c_str(), r.score);
        if (!r.threat_name.empty()) std::printf("  threat=%s", r.threat_name.c_str());
        std::printf("\n");
        for (const Finding& f : r.findings) std::printf("    - %s (+%d): %s\n", f.rule.c_str(), f.score, f.detail.c_str());
        if (!r.message.empty()) std::printf("    %s\n", r.message.c_str());
        if (r.verdict == Verdict::Malicious && a.quarantine) {
            QuarantineEntry e;
            std::string err;
            if (agent.quarantine().quarantine_file(r.path, r.threat_name, e, err)) {
                std::printf("    quarantined: %s\n", e.id.c_str());
            } else {
                std::printf("    quarantine failed: %s\n", err.c_str());
            }
        }
    });

    std::printf("\nscanned=%llu clean=%llu suspicious=%llu malicious=%llu skipped=%llu errors=%llu\n",
                static_cast<unsigned long long>(sum.scanned), static_cast<unsigned long long>(sum.clean),
                static_cast<unsigned long long>(sum.suspicious), static_cast<unsigned long long>(sum.malicious),
                static_cast<unsigned long long>(sum.skipped), static_cast<unsigned long long>(sum.errors));
    return sum.malicious > 0 ? 1 : 0;
}

int cmd_hash(const Args& a) {
    if (a.positional.empty()) {
        usage();
        return 2;
    }
    const auto h = util::sha256_file(util::path_from_utf8(a.positional[0]));
    if (!h) {
        std::fprintf(stderr, "cannot read file\n");
        return 3;
    }
    std::printf("%s\n", h->c_str());
    return 0;
}

int cmd_pe(const Args& a) {
    if (a.positional.empty()) {
        usage();
        return 2;
    }
    std::vector<std::uint8_t> data;
    if (!util::read_file(util::path_from_utf8(a.positional[0]), data, 1ull << 30)) {
        std::fprintf(stderr, "cannot read file\n");
        return 3;
    }
    const auto pe = analyze_pe(data.data(), data.size());
    if (!pe) {
        std::puts("not a valid PE image");
        return 1;
    }
    std::printf("arch=%s dll=%s signed(dir present)=%s entry=0x%x timestamp=%u\n", pe->is_64bit ? "x64" : "x86",
                pe->is_dll ? "yes" : "no", pe->has_certificate ? "yes" : "no", pe->entry_point, pe->timestamp);
    for (const PeSection& s : pe->sections) {
        std::printf("  section %-8s va=0x%08x raw=0x%08x size=0x%08x entropy=%.2f%s%s\n", s.name.c_str(),
                    s.virtual_address, s.raw_offset, s.raw_size, s.entropy, s.executable() ? " X" : "",
                    s.writable() ? " W" : "");
    }
    std::printf("  imports: %zu dlls, %zu functions\n", pe->imported_dlls.size(), pe->imported_functions.size());
    for (const std::string& d : pe->imported_dlls) std::printf("    %s\n", d.c_str());
    return 0;
}

int cmd_quarantine(const Args& a) {
    if (a.positional.empty()) {
        usage();
        return 2;
    }
    Quarantine q(data_dir_of(a) / "quarantine");
    const std::string& sub = a.positional[0];
    std::string err;
    if (sub == "list") {
        const auto entries = q.list();
        for (const QuarantineEntry& e : entries) {
            std::printf("%s  %s  %s  %s\n", e.id.c_str(), e.time.c_str(), e.threat.c_str(), e.original_path.c_str());
        }
        std::printf("%zu item(s)\n", entries.size());
        return 0;
    }
    if (a.positional.size() < 2) {
        usage();
        return 2;
    }
    if (sub == "restore") {
        if (!q.restore(a.positional[1], a.to.empty() ? fs::path() : util::path_from_utf8(a.to), false, err)) {
            std::fprintf(stderr, "restore failed: %s\n", err.c_str());
            return 1;
        }
        std::puts("restored");
        return 0;
    }
    if (sub == "delete") {
        if (!q.remove(a.positional[1], err)) {
            std::fprintf(stderr, "delete failed: %s\n", err.c_str());
            return 1;
        }
        std::puts("deleted");
        return 0;
    }
    usage();
    return 2;
}

}

int main(int argc, char** argv) {
    log::set_level(log::Level::Warn);
    if (argc < 2) {
        usage();
        return 2;
    }
    const std::string cmd = argv[1];
    if (cmd == "behavior-replay") return run_behavior_replay(argc, argv, 2);
    if (cmd == "behavior-rules") return run_behavior_rules();
    const Args a = parse(argc, argv, 2);
    if (cmd == "scan") return cmd_scan(a);
    if (cmd == "hash") return cmd_hash(a);
    if (cmd == "pe") return cmd_pe(a);
    if (cmd == "quarantine") return cmd_quarantine(a);
    usage();
    return 2;
}
