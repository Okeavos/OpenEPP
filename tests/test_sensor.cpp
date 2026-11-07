#include "test_framework.h"

#include "behavior/alert_store.h"
#include "behavior/es_parser.h"
#include "behavior/rules.h"
#include "common/util.h"
#include "scanner/scan_engine.h"
#include "sensor/alert_enricher.h"
#include "sensor/conn_tracker.h"
#include "sensor/proc_snapshot.h"
#include "sensor/eslogger_source.h"
#include "sensor/sensor_service.h"
#include "sensor/socket_poller.h"

#include <chrono>
#include <fstream>
#include <atomic>
#include <functional>
#include <mutex>
#include <unistd.h>
#include <thread>

using namespace sec;
using namespace sec::behavior;
using namespace sec::sensor;
namespace fs = std::filesystem;

namespace {

bool wait_until(const std::function<bool()>& cond, int timeout_ms = 5000) {
    const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < end) {
        if (cond()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return cond();
}

Alert make_alert(std::int64_t t, int level = 1, const std::string& title = "title") {
    Alert a;
    a.time_ms = t;
    a.level = level;
    a.score = 70;
    a.pid = 42;
    a.process_path = "/tmp/x";
    a.title = title;
    a.rule_ids = {"r.one", "r.two"};
    a.techniques = {"T1059"};
    a.chain = {"launchd(1)", "bash(10)", "x(42)"};
    a.detail = "exec /tmp/x";
    return a;
}

std::string normalized_exec(int pid, int ppid, const char* path, const char* signing, long long t) {
    return std::string(R"({"type":"exec","time_ms":)") + std::to_string(t) + R"(,"pid":)" + std::to_string(pid) +
           R"(,"ppid":)" + std::to_string(ppid) + R"(,"path":")" + path + R"(","args":[")" + path +
           R"("],"signing":")" + signing + R"("})";
}

RuleSet net_rules() {
    RuleSet rs;
    CHECK(load_ruleset_text(R"({"rules":[
        {"id":"r.pub","title":"public connect","event":"net","score":100,"tag":"c2_candidate","when":{"remote_public":true}},
        {"id":"r.unsigned","title":"unsigned exec","event":"exec","score":100,"when":{"unsigned_process":true}}]})",
                            rs, nullptr));
    return rs;
}

}

TEST(alert_tsv_roundtrip_with_awkward_characters) {
    Alert a = make_alert(123456, 2, "tab\there\nnewline \\ backslash");
    a.detail = "line1\nline2\t\"q\"";
    a.process_path = "/Users/me/My Files/ç.app";
    const std::string line = alert_to_tsv(a);
    CHECK(line.find('\n') == std::string::npos);
    Alert b;
    CHECK(alert_from_tsv(line, b));
    CHECK(b.time_ms == a.time_ms);
    CHECK(b.level == 2);
    CHECK(b.title == a.title);
    CHECK(b.detail == a.detail);
    CHECK(b.process_path == a.process_path);
    CHECK(b.rule_ids == a.rule_ids);
    CHECK(b.chain == a.chain);
    CHECK(b.techniques == a.techniques);

    Alert empty_lists = make_alert(1);
    empty_lists.rule_ids.clear();
    empty_lists.techniques.clear();
    empty_lists.chain.clear();
    CHECK(alert_from_tsv(alert_to_tsv(empty_lists), b));
    CHECK(b.rule_ids.empty() && b.chain.empty());

    CHECK(!alert_from_tsv("garbage", b));
    CHECK(!alert_from_tsv("1\t9\t1\t1\ta\tb\tc\td\te\tf", b));  // bad level
    CHECK(!alert_from_tsv("x\t1\t1\t1\ta\tb\tc\td\te\tf", b));  // bad number
}

TEST(alert_log_and_feed_basic_flow) {
    sec_test::TempDir dir;
    const fs::path file = dir.path() / "a" / "alerts.tsv";
    AlertLog log(file);
    AlertFeed feed(file, dir.path() / "seen.txt");

    feed.poll();
    CHECK(feed.total() == 0);
    CHECK(feed.unseen() == 0);

    CHECK(log.append(make_alert(1000)));
    CHECK(log.append(make_alert(2000, 2, "second")));
    feed.poll();
    CHECK(feed.total() == 2);
    CHECK(feed.unseen() == 2);
    const auto recent = feed.recent();
    CHECK(recent.size() == 2);
    CHECK(recent[0].title == "second");
    CHECK(recent[0].level == 2);

    feed.mark_seen();
    CHECK(feed.unseen() == 0);
    CHECK(log.append(make_alert(3000, 1, "third")));
    feed.poll();
    CHECK(feed.unseen() == 1);
    CHECK(feed.recent()[0].title == "third");
    feed.poll();
    CHECK(feed.total() == 3);
}

TEST(alert_feed_first_poll_counts_history_as_seen_and_persists_seen_state) {
    sec_test::TempDir dir;
    const fs::path file = dir.path() / "alerts.tsv";
    const fs::path seen = dir.path() / "seen.txt";
    {
        AlertLog log(file);
        log.append(make_alert(1000));
        log.append(make_alert(2000));
    }
    {
        AlertFeed feed(file, seen);
        feed.poll();
        CHECK(feed.total() == 2);
        CHECK(feed.unseen() == 0);
    }
    {
        AlertLog log(file);
        log.append(make_alert(5000, 2, "new while app was closed"));
    }
    AlertFeed feed2(file, seen);
    feed2.poll();
    CHECK(feed2.total() == 3);
    CHECK(feed2.unseen() == 1);
    feed2.mark_seen();

    AlertFeed feed3(file, seen);
    feed3.poll();
    CHECK(feed3.unseen() == 0);
}

TEST(alert_feed_handles_partial_lines_truncation_and_garbage) {
    sec_test::TempDir dir;
    const fs::path file = dir.path() / "alerts.tsv";
    AlertFeed feed(file, dir.path() / "seen.txt");
    feed.poll();

    const std::string line = alert_to_tsv(make_alert(1000)) + "\n";
    {
        std::ofstream out(file, std::ios::binary | std::ios::app);
        out << line.substr(0, 20);
    }
    feed.poll();
    CHECK(feed.total() == 0);
    {
        std::ofstream out(file, std::ios::binary | std::ios::app);
        out << line.substr(20) << "this is not an alert\n" << alert_to_tsv(make_alert(2000)) << "\n";
    }
    feed.poll();
    CHECK(feed.total() == 2);

    {
        std::ofstream out(file, std::ios::binary | std::ios::trunc);
        out << alert_to_tsv(make_alert(2000)) << "\n" << alert_to_tsv(make_alert(3000)) << "\n";
    }
    feed.poll();
    CHECK(feed.total() == 3);  // only the new one is added again
    CHECK(feed.recent().size() == 3);
}

TEST(alert_log_trims_old_entries) {
    sec_test::TempDir dir;
    const fs::path file = dir.path() / "alerts.tsv";
    AlertLog log(file, 20);
    for (int i = 1; i <= 260; ++i) CHECK(log.append(make_alert(i)));

    std::ifstream in(file);
    std::string line;
    int lines = 0;
    std::int64_t first = 0;
    while (std::getline(in, line)) {
        Alert a;
        CHECK(alert_from_tsv(line, a));
        if (lines == 0) first = a.time_ms;
        ++lines;
    }
    CHECK(lines <= 20 + 200);
    CHECK(lines >= 20);
    CHECK(first > 1);

    AlertFeed feed(file, dir.path() / "seen.txt", 50);
    feed.poll();
    CHECK(feed.recent().size() <= 50);
    CHECK(feed.recent().front().time_ms == 260);
}

TEST(sensor_status_roundtrip_and_freshness) {
    sec_test::TempDir dir;
    const fs::path file = dir.path() / "status.txt";
    SensorStatus s;
    s.pid = 77;
    s.started_ms = 1000;
    s.updated_ms = 5000;
    s.eslogger = "failed";
    s.sockets = "running";
    s.events = 12;
    s.dropped = 1;
    s.alerts = 3;
    s.parse_errors = 4;
    s.last_error = "eslogger exited with code 1:\nneeds Full Disk Access";
    s.rules_error = "";
    CHECK(write_status(file, s));
    const auto r = read_status(file);
    CHECK(r.has_value());
    CHECK(r->pid == 77);
    CHECK(r->eslogger == "failed");
    CHECK(r->sockets == "running");
    CHECK(r->events == 12 && r->dropped == 1 && r->alerts == 3 && r->parse_errors == 4);
    CHECK(r->last_error.find("Full Disk Access") != std::string::npos);
    CHECK(r->last_error.find('\n') == std::string::npos);

    CHECK(status_is_fresh(*r, 6000));
    CHECK(!status_is_fresh(*r, 5000 + 25000));
    SensorStatus stopped = *r;
    stopped.updated_ms = 0;
    CHECK(!status_is_fresh(stopped, 100));
    CHECK(!read_status(dir.path() / "missing.txt").has_value());
}

TEST(conn_tracker_emits_only_new_connections) {
    ConnTracker t(false);
    ConnInfo a;
    a.pid = 10;
    a.ppid = 1;
    a.path = "/opt/x";
    a.remote_ip = "203.0.113.9";
    a.remote_port = 443;
    a.local_port = 50000;

    CHECK(t.update({a}, 1000).empty());  // baseline
    CHECK(t.update({a}, 2000).empty());

    ConnInfo b = a;
    b.local_port = 50001;
    auto ev = t.update({a, b}, 3000);
    CHECK(ev.size() == 1);
    CHECK(ev[0].type == EventType::NetConnect);
    CHECK(ev[0].proc.pid == 10);
    CHECK(ev[0].remote_ip == "203.0.113.9");
    CHECK(ev[0].remote_port == 443);
    CHECK(ev[0].time_ms == 3000);

    CHECK(t.update({a}, 4000).empty());      // b closed
    CHECK(t.update({a, b}, 5000).size() == 1);  // b reconnects -> new event

    ConnInfo lo = a;
    lo.remote_ip = "127.0.0.1";
    lo.local_port = 1;
    ConnInfo bad = a;
    bad.pid = 0;
    CHECK(t.update({a, b, lo, bad}, 6000).empty());

    ConnTracker initial(true);
    CHECK(initial.update({a}, 1).size() == 1);
}

TEST(sensor_service_runs_engine_and_writes_alerts) {
    sec_test::TempDir dir;
    AlertLog log(dir.path() / "alerts.tsv");
    int callbacks = 0;
    SensorService svc(net_rules(), IocSet{}, &log, [&](const Alert&) { ++callbacks; });
    svc.start();

    auto submit_line = [&](const std::string& line) {
        ParseResult r = parse_event_line(line);
        CHECK(r.ok());
        svc.submit(std::move(r.event));
    };
    submit_line(normalized_exec(100, 1, "/tmp/payload", "unsigned", 1000));
    submit_line(R"({"type":"net","time_ms":2000,"pid":100,"path":"/tmp/payload","remote_ip":"203.0.113.9","remote_port":4444})");
    svc.flush();

    const SensorStats st = svc.stats();
    CHECK(st.events_processed == 2);
    CHECK(st.alerts == 2);
    CHECK(callbacks == 2);

    AlertFeed feed(dir.path() / "alerts.tsv", dir.path() / "seen.txt");
    feed.poll();
    CHECK(feed.total() == 2);
    svc.stop();
}

TEST(sensor_service_filters_noise_and_keeps_time_monotonic) {
    sec_test::TempDir dir;
    AlertLog log(dir.path() / "alerts.tsv");
    SensorService svc(net_rules(), IocSet{}, &log);
    svc.start();

    Event noisy;
    noisy.type = EventType::FileCreate;
    noisy.proc.pid = 5;
    noisy.file_path = "/Users/me/Library/Caches/com.x/cache.db";
    svc.submit(noisy);
    noisy.file_path = "/Library/Application Support/SecEPP/behavior_alerts.tsv";
    svc.submit(noisy);

    Event own;
    own.type = EventType::Exec;
    own.proc.pid = static_cast<int>(::getpid());
    own.proc.path = "/tmp/self";
    svc.submit(own);

    svc.set_extra_ignored_pid(4242);
    Event child;
    child.type = EventType::Exec;
    child.proc.pid = 4242;
    child.proc.path = "/usr/bin/eslogger";
    svc.submit(child);

    Event late = noisy;
    late.file_path = "/tmp/ok";
    late.time_ms = 5000;
    svc.submit(late);
    late.time_ms = 1000;  // out of order
    svc.submit(late);
    svc.flush();

    const SensorStats st = svc.stats();
    CHECK(st.events_ignored == 4);
    CHECK(st.events_in == 2);
    CHECK(st.events_processed == 2);
    svc.stop();
}

TEST(sensor_service_drops_instead_of_blocking_when_queue_is_full) {
    AlertLog* none = nullptr;
    SensorService svc(net_rules(), IocSet{}, none);
    // worker not started: nothing drains the queue
    Event e;
    e.type = EventType::Exit;
    e.proc.pid = 9;
    for (std::size_t i = 0; i < SensorService::kMaxQueue + 10; ++i) svc.submit(e);
    CHECK(svc.stats().events_dropped == 10);
    svc.flush();  // returns immediately when not running
    svc.start();
    svc.flush();
    CHECK(svc.stats().events_processed == SensorService::kMaxQueue);
    svc.stop();
}

TEST(socket_poller_turns_snapshots_into_events) {
    sec_test::TempDir dir;
    AlertLog log(dir.path() / "alerts.tsv");
    SensorService svc(net_rules(), IocSet{}, &log);
    svc.start();

    std::atomic<int> call{0};
    SnapshotFn fn = [&](std::vector<ConnInfo>& out) {
        const int n = ++call;
        ConnInfo c;
        c.pid = 300;
        c.ppid = 1;
        c.path = "/opt/agent";
        c.remote_ip = "198.51.100.4";
        c.remote_port = 443;
        c.local_port = 40000;
        out.push_back(c);
        if (n >= 2) {
            c.local_port = 40001;
            out.push_back(c);
        }
        return true;
    };
    SocketPoller poller(fn, 100, svc);
    poller.start();
    CHECK(wait_until([&] { return svc.stats().alerts >= 1; }));
    poller.stop();
    svc.stop();
    CHECK(svc.stats().alerts == 1);  // rule fires once per process
    CHECK(poller.state() == "stopped");

    SocketPoller failing([](std::vector<ConnInfo>&) { return false; }, 100, svc);
    failing.start();
    CHECK(wait_until([&] { return failing.state() == "failed"; }));
    failing.stop();
}

TEST(eslogger_source_reads_events_from_command) {
    sec_test::TempDir dir;
    const fs::path events = dir.path() / "events.jsonl";
    {
        std::ofstream out(events);
        out << normalized_exec(500, 1, "/tmp/dropper", "unsigned", 1000) << "\n";
        out << "this line is not json\n";
        out << R"({"process":{"audit_token":{"pid":1}},"event":{"mmap":{}}})" << "\n";
        out << R"({"process":{"audit_token":{"pid":500},"ppid":1,"executable":{"path":"/tmp/dropper"}},"event":{"close":{"modified": false,"target":{"path":"/tmp/a"}}}})" << "\n";
        out << R"({"type":"net","time_ms":2000,"pid":500,"path":"/tmp/dropper","remote_ip":"203.0.113.9","remote_port":4444})" << "\n";
    }
    AlertLog log(dir.path() / "alerts.tsv");
    SensorService svc(net_rules(), IocSet{}, &log);
    svc.start();

    EsloggerSource src({"/bin/sh", "-c", "cat '" + events.string() + "'; sleep 30"}, svc);
    src.start();
    CHECK(wait_until([&] { return svc.stats().alerts >= 2; }));
    const auto st = src.status();
    CHECK(st.lines >= 4);
    CHECK(st.parse_errors == 1);
    CHECK(st.state == "starting" || st.state == "running");

    const auto t0 = std::chrono::steady_clock::now();
    src.stop();
    CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(4));  // sleep 30 was terminated
    CHECK(src.status().state == "stopped");
    svc.stop();
}

TEST(eslogger_source_reports_failure_and_restarts) {
    sec_test::TempDir dir;
    SensorService svc(net_rules(), IocSet{}, nullptr);
    svc.start();

    EsloggerSource src({"/bin/sh", "-c", "echo 'eslogger: not permitted (needs Full Disk Access)' >&2; exit 3"}, svc);
    src.set_backoff(50, 100);
    src.start();
    CHECK(wait_until([&] { return src.status().restarts >= 2; }));
    const auto st = src.status();
    CHECK(st.last_error.find("code 3") != std::string::npos);
    CHECK(st.last_error.find("Full Disk Access") != std::string::npos);
    src.stop();

    EsloggerSource missing({"/nonexistent/eslogger-binary"}, svc);
    missing.set_backoff(50, 100);
    missing.start();
    CHECK(wait_until([&] { return missing.status().state == "failed"; }));
    CHECK(missing.status().last_error.find("cannot start") != std::string::npos);
    missing.stop();
    svc.stop();
}

TEST(eslogger_source_survives_huge_and_broken_lines) {
    SensorService svc(net_rules(), IocSet{}, nullptr);
    svc.start();
    EsloggerSource src({"/bin/sh", "-c",
                        "head -c 300000 /dev/zero | tr '\\0' 'a'; echo; printf '{\"type\":\"exit\",\"pid\":7}\\n'; sleep 30"},
                       svc);
    src.start();
    CHECK(wait_until([&] { return src.status().lines >= 2; }));
    CHECK(src.status().parse_errors == 1);
    CHECK(wait_until([&] { return svc.stats().events_processed >= 1; }));
    src.stop();
    svc.stop();
}

namespace {

const char kEicar[] = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

void write_file(const fs::path& p, const std::string& data) {
    std::ofstream out(p, std::ios::binary);
    out << data;
}

}

TEST(enricher_scans_suspect_files_and_raises_level) {
    sec_test::TempDir tmp;
    write_file(tmp.path() / "clean.bin", "just some harmless bytes");
    write_file(tmp.path() / "bad.bin", std::string("MZ") + kEicar);

    ScanEngine scan;
    AlertEnricher enrich(&scan);

    Alert a = make_alert(1000, 1, "의심 활동");
    a.suspect_paths = {util::path_to_utf8(tmp.path() / "clean.bin"), util::path_to_utf8(tmp.path() / "missing.bin")};
    enrich(a);
    CHECK(a.files.size() == 2);
    CHECK(a.level == 1);
    CHECK(a.files[0].find("sha256:") != std::string::npos);
    CHECK(a.files[0].find("이상 없음") != std::string::npos);
    CHECK(a.files[1].find("파일 없음") != std::string::npos);

    Alert b = make_alert(2000, 1, "의심 활동");
    b.suspect_paths = {util::path_to_utf8(tmp.path() / "bad.bin")};
    enrich(b);
    CHECK(b.files.size() == 1);
    CHECK(b.level == 2);
    CHECK(b.title.find("스캐너 악성 판정") != std::string::npos);
    CHECK(b.files[0].find("EICAR") != std::string::npos);
    CHECK(std::find(b.rule_ids.begin(), b.rule_ids.end(), "scanner.malicious") != b.rule_ids.end());

    Alert c = make_alert(3000);
    enrich(c);  // nothing to look at
    CHECK(c.files.empty());
    AlertEnricher none(nullptr);
    none(b);  // a null engine is tolerated
}

TEST(service_enriches_alerts_before_storing_and_reports_hook) {
    sec_test::TempDir tmp;
    const fs::path payload = tmp.path() / "payload";
    write_file(payload, std::string("MZ") + kEicar);
    const std::string payload_path = util::path_to_utf8(payload);

    RuleSet rs;
    CHECK(load_ruleset_text(R"({"rules":[
        {"id":"r.unsigned","title":"unsigned exec","event":"exec","score":100,"when":{"unsigned_process":true}}]})",
                            rs, nullptr));
    AlertLog log(tmp.path() / "alerts.tsv");
    ScanEngine scan;
    AlertEnricher enrich(&scan);

    std::atomic<int> hook_events{0};
    std::atomic<int> hook_alerts{0};
    SensorService svc(std::move(rs), IocSet{}, &log);
    svc.set_enricher([&enrich](Alert& a) { enrich(a); });
    svc.set_event_hook([&](const Event&, std::size_t n) {
        ++hook_events;
        hook_alerts += static_cast<int>(n);
    });
    svc.start();

    const ParseResult r = parse_event_line(normalized_exec(4242, 1, payload_path.c_str(), "unsigned", 1000));
    CHECK(r.ok());
    svc.submit(r.event);
    svc.flush();

    CHECK(hook_events == 1);
    CHECK(hook_alerts == 1);
    svc.stop();

    std::ifstream in(tmp.path() / "alerts.tsv");
    std::string line;
    CHECK(static_cast<bool>(std::getline(in, line)));
    Alert stored;
    CHECK(alert_from_tsv(line, stored));
    CHECK(stored.level == 2);
    CHECK(stored.files.size() == 1);
    if (!stored.files.empty()) CHECK(stored.files[0].find("EICAR") != std::string::npos);
}

TEST(service_seeds_running_processes_before_later_events) {
    RuleSet rs;
    CHECK(load_ruleset_text(R"({"rules":[
        {"id":"r.unsigned_net","title":"unsigned connects","event":"net","score":100,
         "when":{"unsigned_process":true,"remote_public":true}}]})",
                            rs, nullptr));
    std::mutex m;
    std::vector<Alert> got;
    SensorService svc(std::move(rs), IocSet{}, nullptr, [&](const Alert& a) {
        std::lock_guard<std::mutex> lock(m);
        got.push_back(a);
    });
    svc.start();

    ProcessRef p;
    p.pid = 5151;
    p.ppid = 1;
    p.path = "/opt/old/implant";
    p.sig_known = true;  // known to be unsigned
    svc.seed_processes({p});

    // The connection event itself carries no signing information; the seeded state supplies it.
    Event ev;
    ev.type = EventType::NetConnect;
    ev.time_ms = 5000;
    ev.proc.pid = 5151;
    ev.proc.path = "/opt/old/implant";
    ev.remote_ip = "203.0.113.5";
    ev.remote_port = 443;
    svc.submit(ev);
    svc.flush();

    CHECK(svc.stats().seeded == 1);
    std::lock_guard<std::mutex> lock(m);
    CHECK(got.size() == 1);
    svc.stop();
}

TEST(snapshot_lists_this_process) {
    const std::vector<ProcessRef> procs = snapshot_processes();
    CHECK(!procs.empty());
    const int me = static_cast<int>(::getpid());
    bool found = false;
    for (const ProcessRef& p : procs) {
        if (p.pid != me) continue;
        found = true;
        CHECK(!p.path.empty());
        CHECK(p.ppid > 0);
        CHECK(!p.args.empty());
#if defined(__APPLE__)
        CHECK(p.sig_known);  // the test binary is at least ad-hoc signed by the linker on arm64
#endif
    }
    CHECK(found);
}
