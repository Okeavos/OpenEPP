#include "test_framework.h"

#include "agent/agent.h"
#include "agent/detection_store.h"
#include "agent/realtime.h"
#include "pe_builder.h"

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <thread>

using namespace sec;
using namespace sec_test;
namespace fs = std::filesystem;
using namespace std::chrono_literals;

namespace {

const char kEicarStr[] = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

void write_bytes(const fs::path& p, const void* data, std::size_t n) {
    fs::create_directories(p.parent_path());
    std::ofstream f(p, std::ios::binary);
    f.write(static_cast<const char*>(data), static_cast<std::streamsize>(n));
}

void write_text(const fs::path& p, const std::string& s) { write_bytes(p, s.data(), s.size()); }

template <typename Pred>
bool wait_for(Pred pred, int timeout_ms = 5000) {
    for (int waited = 0; waited < timeout_ms; waited += 20) {
        if (pred()) return true;
        std::this_thread::sleep_for(20ms);
    }
    return pred();
}

AgentConfig make_cfg(const fs::path& root, bool auto_quarantine) {
    AgentConfig cfg;
    cfg.data_dir = root / "data";
    cfg.auto_quarantine = auto_quarantine;
    return cfg;
}

}

TEST(detection_store_persists_and_tracks_unseen) {
    TempDir tmp;
    const fs::path file = tmp.path() / "d" / "det.tsv";

    DetectionRecord r;
    r.time = "2026-01-01T00:00:00Z";
    r.path = "/a/b\tc";
    r.verdict = "malicious";
    r.threat = "T";
    r.score = 100;
    r.sha256 = "ab";
    r.action = "quarantined";

    {
        DetectionStore s(file);
        s.load();
        CHECK(s.total() == 0);
        s.add(r);
        s.add(r);
        CHECK(s.total() == 2);
        CHECK(s.unseen() == 2);
        s.mark_seen();
        CHECK(s.unseen() == 0);
        s.add(r);
        CHECK(s.unseen() == 1);
    }
    {
        DetectionStore s(file);
        s.load();
        CHECK(s.total() == 3);
        CHECK(s.unseen() == 0);
        const auto v = s.recent();
        CHECK(v.size() == 3);
        CHECK(v[0].path == "/a/b c");
        CHECK(v[0].action == "quarantined");
        CHECK(v[0].score == 100);
    }
}

TEST(detection_store_dedups_unresolved_repeats_only) {
    TempDir tmp;
    DetectionStore s(tmp.path() / "det.tsv");
    DetectionRecord r;
    r.path = "/a/file.exe";
    r.sha256 = "aa";
    r.action = "none";
    s.add(r);
    s.add(r);
    CHECK(s.total() == 1);

    r.sha256 = "bb";
    s.add(r);
    CHECK(s.total() == 2);

    DetectionRecord q;
    q.path = "/a/dropper.exe";
    q.sha256 = "cc";
    q.action = "quarantined";
    s.add(q);
    s.add(q);
    CHECK(s.total() == 4);
}

TEST(detection_store_caps_memory_but_counts_all) {
    TempDir tmp;
    DetectionStore s(tmp.path() / "det.tsv", 2);
    for (int i = 0; i < 5; ++i) {
        DetectionRecord r;
        r.path = "/f" + std::to_string(i);
        s.add(r);
    }
    CHECK(s.total() == 5);
    const auto v = s.recent();
    CHECK(v.size() == 2);
    CHECK(v[0].path == "/f4");
    CHECK(v[1].path == "/f3");
}

TEST(realtime_detects_and_quarantines_new_files) {
    TempDir tmp;
    Agent agent(make_cfg(tmp.path(), true));
    CHECK(agent.initialize());
    DetectionStore store(tmp.path() / "data" / "det.tsv");
    agent.set_detection_store(&store);

    RealtimeScanner rt(agent, 50ms);
    rt.add_ignore_prefix(tmp.path() / "data");
    rt.start();

    write_text(tmp.path() / "watch" / "e.com", kEicarStr);
    write_text(tmp.path() / "watch" / "c.txt", "hello");
    rt.notify(tmp.path() / "watch" / "e.com");
    rt.notify(tmp.path() / "watch" / "c.txt");

    CHECK(wait_for([&] { return store.total() == 1 && rt.stats().scanned >= 2; }));
    CHECK(!fs::exists(tmp.path() / "watch" / "e.com"));
    CHECK(fs::exists(tmp.path() / "watch" / "c.txt"));
    const auto v = store.recent();
    CHECK(v.size() == 1);
    if (!v.empty()) {
        CHECK(v[0].verdict == "malicious");
        CHECK(v[0].action == "quarantined");
        CHECK(v[0].threat == "EICAR-Test-File");
    }
    rt.stop();
}

TEST(realtime_coalesces_bursts_of_events) {
    TempDir tmp;
    Agent agent(make_cfg(tmp.path(), false));
    CHECK(agent.initialize());
    RealtimeScanner rt(agent, 150ms);
    rt.start();

    const fs::path f = tmp.path() / "growing.bin";
    write_text(f, "x");
    for (int i = 0; i < 10; ++i) {
        rt.notify(f);
        std::this_thread::sleep_for(10ms);
    }
    CHECK(wait_for([&] { return rt.stats().scanned >= 1; }));
    std::this_thread::sleep_for(400ms);
    CHECK(rt.stats().scanned == 1);
    CHECK(rt.stats().events == 10);
    rt.stop();
}

TEST(realtime_ignores_own_data_noise_missing_and_paused) {
    TempDir tmp;
    Agent agent(make_cfg(tmp.path(), true));
    CHECK(agent.initialize());
    DetectionStore store(tmp.path() / "data" / "det.tsv");
    agent.set_detection_store(&store);
    RealtimeScanner rt(agent, 30ms);
    rt.add_ignore_prefix(tmp.path() / "data");
    rt.start();

    write_text(tmp.path() / "data" / "inside.com", kEicarStr);
    write_text(tmp.path() / "dl" / "movie.crdownload", kEicarStr);
    write_text(tmp.path() / "dl" / "paused.com", kEicarStr);
    rt.notify(tmp.path() / "data" / "inside.com");
    rt.notify(tmp.path() / "dl" / "movie.crdownload");
    rt.notify(tmp.path() / "dl" / "does_not_exist.bin");
    rt.set_paused(true);
    rt.notify(tmp.path() / "dl" / "paused.com");

    std::this_thread::sleep_for(400ms);
    CHECK(rt.stats().scanned == 0);
    CHECK(store.total() == 0);
    CHECK(fs::exists(tmp.path() / "dl" / "paused.com"));

    rt.set_paused(false);
    rt.notify(tmp.path() / "dl" / "paused.com");
    CHECK(wait_for([&] { return store.total() == 1; }));
    rt.stop();
}

TEST(realtime_records_suspicious_without_quarantine) {
    TempDir tmp;
    Agent agent(make_cfg(tmp.path(), true));
    CHECK(agent.initialize());
    DetectionStore store(tmp.path() / "data" / "det.tsv");
    agent.set_detection_store(&store);
    RealtimeScanner rt(agent, 30ms);
    rt.start();

    SectionSpec text{".text", std::vector<std::uint8_t>(800, 0x90), 0x60000020};
    const auto img = make_pe({text}, {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "ExitProcess",
                                      "CreateFileW", "ReadFile", "CloseHandle"});
    const fs::path f = tmp.path() / "dl" / "inj.exe";
    write_bytes(f, img.data(), img.size());
    rt.notify(f);

    CHECK(wait_for([&] { return store.total() == 1; }));
    const auto v = store.recent();
    CHECK(!v.empty());
    if (!v.empty()) {
        CHECK(v[0].verdict == "suspicious");
        CHECK(v[0].action == "none");
        CHECK(!v[0].threat.empty());
    }
    CHECK(fs::exists(f));
    rt.stop();
}

TEST(agent_config_watch_paths_and_home_expansion) {
    Config c;
    c.set("watch_paths", "~/Downloads; /opt/x ;");
    c.set("realtime", "false");
    const AgentConfig a = AgentConfig::from_config(c);
    CHECK(a.watch_paths.size() == 2);
    CHECK(!a.realtime_enabled);
    CHECK(a.watch_paths[1] == fs::path("/opt/x"));
    CHECK(a.watch_paths[0].filename() == "Downloads");
    CHECK(a.watch_paths[0].is_absolute() || std::getenv("HOME") == nullptr);

    const AgentConfig d = AgentConfig::from_config(Config());
    CHECK(d.realtime_enabled);
    CHECK(!d.watch_paths.empty() || std::getenv("HOME") == nullptr);
}
