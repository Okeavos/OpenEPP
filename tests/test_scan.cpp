#include "test_framework.h"

#include "agent/agent.h"
#include "common/sha256.h"
#include "common/util.h"
#include "pe_builder.h"
#include "scanner/quarantine.h"
#include "scanner/scan_engine.h"

#include <fstream>

using namespace sec;
using namespace sec_test;
namespace fs = std::filesystem;

namespace {

const char kEicarStr[] = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

void write_bytes(const fs::path& p, const void* data, std::size_t n) {
    std::ofstream f(p, std::ios::binary);
    f.write(static_cast<const char*>(data), static_cast<std::streamsize>(n));
}

void write_text(const fs::path& p, const std::string& s) { write_bytes(p, s.data(), s.size()); }

}

TEST(scan_clean_text_file) {
    TempDir tmp;
    write_text(tmp.path() / "a.txt", "just some harmless text");
    ScanEngine eng;
    const ScanResult r = eng.scan_file(tmp.path() / "a.txt");
    CHECK(r.verdict == Verdict::Clean);
    CHECK(r.score == 0);
    CHECK(r.sha256.size() == 64);
}

TEST(scan_detects_eicar_inside_larger_file) {
    TempDir tmp;
    std::string content(5000, 'z');
    content += kEicarStr;
    content += std::string(777, 'q');
    write_text(tmp.path() / "e.bin", content);
    ScanEngine eng;
    const ScanResult r = eng.scan_file(tmp.path() / "e.bin");
    CHECK(r.verdict == Verdict::Malicious);
    CHECK(r.threat_name == "EICAR-Test-File");
}

TEST(scan_hash_db_hit) {
    TempDir tmp;
    write_text(tmp.path() / "x.bin", "pretend this is malware");
    ScanEngine eng;
    const std::string h = Sha256::to_hex(Sha256::of("pretend this is malware", 23));
    CHECK(eng.hash_db().add(h, "Trojan.Unit"));
    const ScanResult r = eng.scan_file(tmp.path() / "x.bin");
    CHECK(r.verdict == Verdict::Malicious);
    CHECK(r.threat_name == "Trojan.Unit");
    CHECK(r.score == 100);
}

TEST(scan_custom_pattern) {
    TempDir tmp;
    write_text(tmp.path() / "p.bin", "aaaa-EVIL-MARKER-bbbb");
    ScanEngine eng;
    eng.add_pattern({"Custom.Marker", {'E', 'V', 'I', 'L', '-', 'M', 'A', 'R', 'K', 'E', 'R'}});
    CHECK(eng.scan_file(tmp.path() / "p.bin").verdict == Verdict::Malicious);
}

TEST(scan_pe_injection_imports_are_suspicious) {
    TempDir tmp;
    SectionSpec text{".text", std::vector<std::uint8_t>(800, 0x90), 0x60000020};
    const auto img = make_pe({text}, {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "ExitProcess",
                                      "CreateFileW", "ReadFile", "CloseHandle"});
    write_bytes(tmp.path() / "inj.exe", img.data(), img.size());
    ScanEngine eng;
    const ScanResult r = eng.scan_file(tmp.path() / "inj.exe");
    CHECK(r.verdict == Verdict::Suspicious);
    bool found = false;
    for (const Finding& f : r.findings) found |= (f.rule == "pe.process_injection_imports");
    CHECK(found);
}

TEST(scan_pe_packed_wx_section_is_suspicious) {
    TempDir tmp;
    SectionSpec packed{"UPX1", random_bytes(8192), 0xE0000020};  // exec + read + write
    const auto img = make_pe({packed}, {"LoadLibraryA", "GetProcAddress"});
    write_bytes(tmp.path() / "packed.exe", img.data(), img.size());
    ScanEngine eng;
    const ScanResult r = eng.scan_file(tmp.path() / "packed.exe");
    CHECK(r.verdict == Verdict::Suspicious);
    CHECK(r.score >= 40);
}

TEST(scan_benign_pe_is_clean) {
    TempDir tmp;
    SectionSpec text{".text", std::vector<std::uint8_t>(1200, 0x90), 0x60000020};
    SectionSpec data{".data", std::vector<std::uint8_t>(600, 0x01), 0xC0000040};
    const auto img = make_pe({text, data}, {"CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "ExitProcess",
                                            "GetLastError", "HeapAlloc", "HeapFree"});
    write_bytes(tmp.path() / "ok.exe", img.data(), img.size());
    ScanEngine eng;
    CHECK(eng.scan_file(tmp.path() / "ok.exe").verdict == Verdict::Clean);
}

TEST(scan_skips_oversize_and_missing) {
    TempDir tmp;
    write_text(tmp.path() / "big.bin", std::string(4096, 'a'));
    ScanEngine eng;
    ScanOptions o;
    o.max_file_size = 1024;
    eng.set_options(o);
    CHECK(eng.scan_file(tmp.path() / "big.bin").verdict == Verdict::Skipped);
    CHECK(eng.scan_file(tmp.path() / "nope.bin").verdict == Verdict::Skipped);
}

TEST(scan_directory_summary_and_cancel) {
    TempDir tmp;
    fs::create_directories(tmp.path() / "sub" / "deep");
    write_text(tmp.path() / "c1.txt", "clean one");
    write_text(tmp.path() / "sub" / "c2.txt", "clean two");
    write_text(tmp.path() / "sub" / "deep" / "bad.com", kEicarStr);
    ScanEngine eng;

    int seen = 0;
    const ScanSummary s = eng.scan_path(tmp.path(), [&](const ScanResult&) { ++seen; });
    CHECK(seen == 3);
    CHECK(s.scanned == 3);
    CHECK(s.malicious == 1);
    CHECK(s.clean == 2);

    std::atomic<bool> cancel{true};
    const ScanSummary c = eng.scan_path(tmp.path(), nullptr, &cancel);
    CHECK(c.cancelled);
    CHECK(c.scanned == 0);
}

TEST(quarantine_roundtrip_and_integrity) {
    TempDir tmp;
    const fs::path victim = tmp.path() / "victim.bin";
    const auto payload = random_bytes(3 * 1024 * 1024 + 17, 99);  // spans multiple 1 MiB chunks
    write_bytes(victim, payload.data(), payload.size());
    const std::string before = *util::sha256_file(victim);

    Quarantine q(tmp.path() / "q");
    QuarantineEntry e;
    std::string err;
    CHECK(q.quarantine_file(victim, "Test.Threat", e, err));
    CHECK(!fs::exists(victim));
    CHECK(e.sha256 == before);
    CHECK(q.list().size() == 1);

    // The stored payload must not equal the original bytes.
    CHECK(*util::sha256_file(q.directory() / (e.id + ".qf")) != before);

    CHECK(q.restore(e.id, {}, false, err));
    CHECK(fs::exists(victim));
    CHECK(*util::sha256_file(victim) == before);
    CHECK(q.list().empty());
}

TEST(quarantine_rejects_bad_ids_and_overwrite) {
    TempDir tmp;
    const fs::path f = tmp.path() / "f.bin";
    write_text(f, "payload");
    Quarantine q(tmp.path() / "q");
    QuarantineEntry e;
    std::string err;
    CHECK(q.quarantine_file(f, "T", e, err));

    CHECK(!q.restore("../../etc/passwd", {}, false, err));  // path traversal attempt
    CHECK(!q.restore("0000000000000000-00000000", {}, false, err));

    write_text(f, "something new now at the original path");
    CHECK(!q.restore(e.id, {}, false, err));  // would overwrite
    CHECK(q.restore(e.id, tmp.path() / "elsewhere.bin", false, err));
    CHECK(fs::exists(tmp.path() / "elsewhere.bin"));
}

TEST(quarantine_detects_tampered_payload) {
    TempDir tmp;
    const fs::path f = tmp.path() / "f.bin";
    write_text(f, "important bytes");
    Quarantine q(tmp.path() / "q");
    QuarantineEntry e;
    std::string err;
    CHECK(q.quarantine_file(f, "T", e, err));

    {
        std::fstream p(q.directory() / (e.id + ".qf"), std::ios::in | std::ios::out | std::ios::binary);
        p.seekp(10);
        p.put('!');
    }
    const fs::path dest = tmp.path() / "restored.bin";
    CHECK(!q.restore(e.id, dest, false, err));
    CHECK(!fs::exists(dest));  // corrupted restore must not be left behind
}

TEST(agent_scan_with_auto_quarantine) {
    TempDir tmp;
    fs::create_directories(tmp.path() / "target");
    write_text(tmp.path() / "target" / "ok.txt", "fine");
    write_text(tmp.path() / "target" / "bad.com", kEicarStr);

    AgentConfig cfg;
    cfg.data_dir = tmp.path() / "data";
    cfg.scan_paths.push_back(tmp.path() / "target");
    cfg.auto_quarantine = true;
    Agent agent(cfg);
    CHECK(agent.initialize());
    const ScanSummary s = agent.scan_now();
    CHECK(s.malicious == 1);
    CHECK(!fs::exists(tmp.path() / "target" / "bad.com"));
    CHECK(fs::exists(tmp.path() / "target" / "ok.txt"));
    CHECK(agent.quarantine().list().size() == 1);
}
