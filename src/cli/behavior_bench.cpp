// sec-cli behavior-bench [--processes N] [--seed S]
// Synthesises a realistic event mix (mostly benign process activity, a little network and file I/O)
// and measures how fast the engine and the parsers handle it.

#include "cli/behavior_cmd.h"

#include "behavior/engine.h"
#include "behavior/es_parser.h"
#include "behavior/rules.h"

#include <chrono>
#include <map>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <string>
#include <vector>

using namespace sec;

namespace {

struct Proto {
    const char* path;
    std::vector<std::string> args;
    const char* signing;
    bool talks_out = false;  // makes outbound HTTPS connections
};

const std::vector<Proto>& protos() {
    static const std::vector<Proto> p = {
        {"/bin/zsh", {"zsh", "-l"}, "platform", false},
        {"/bin/bash", {"bash", "-c", "make -j8 all"}, "platform"},
        {"/usr/bin/git", {"git", "status", "--porcelain"}, "platform", true},
        {"/usr/bin/clang", {"clang", "-c", "-O2", "src/main.c", "-o", "build/main.o"}, "platform"},
        {"/usr/local/bin/node", {"node", "/usr/local/lib/node_modules/npm/bin/npm-cli.js", "run", "build"},
         "team:HX7739G8FX", true},
        {"/usr/bin/python3", {"python3", "-m", "pytest", "-q", "tests/"}, "platform"},
        {"/bin/ls", {"ls", "-la", "/Users/dev/project"}, "platform"},
        {"/usr/bin/grep", {"grep", "-rn", "TODO", "src"}, "platform"},
        {"/usr/bin/curl", {"curl", "-s", "https://api.github.com/repos/x/y"}, "platform", true},
        {"/Applications/Slack.app/Contents/MacOS/Slack", {"Slack"}, "team:BQR82RBBHL", true},
        {"/usr/libexec/xpcproxy", {"xpcproxy", "com.apple.mdworker.shared"}, "platform"},
        {"/System/Library/Frameworks/CoreServices.framework/mdworker_shared", {"mdworker_shared", "-s", "mdworker"},
         "platform"},
        {"/opt/homebrew/bin/rg", {"rg", "--json", "pattern", "."}, "team:unknown"},
        {"/Users/dev/project/build/app", {"app", "--port", "8080"}, "adhoc"},
    };
    return p;
}

void set_signing(behavior::ProcessRef& r, const std::string& s) {
    r.sig_known = true;
    if (s == "platform") r.platform_binary = true;
    else if (s.rfind("team:", 0) == 0) r.team_id = s.substr(5);
}

std::vector<behavior::Event> synthesize(int processes, unsigned seed) {
    std::mt19937 rng(seed);
    std::vector<behavior::Event> evs;
    evs.reserve(static_cast<std::size_t>(processes) * 8);
    std::int64_t t = 1'800'000'000'000LL;
    std::vector<int> live = {1, 300, 301, 302};
    int next_pid = 1000;
    for (int i = 0; i < processes; ++i) {
        const Proto& p = protos()[rng() % protos().size()];
        const int ppid = live[rng() % live.size()];
        const int pid = next_pid++;
        if (next_pid > 99000) next_pid = 1000;

        behavior::Event fork;
        fork.type = behavior::EventType::Fork;
        fork.time_ms = t += 1 + rng() % 5;
        fork.proc.pid = pid;
        fork.proc.ppid = ppid;
        evs.push_back(fork);

        behavior::Event ex;
        ex.type = behavior::EventType::Exec;
        ex.time_ms = t += 1;
        ex.proc.pid = pid;
        ex.proc.ppid = ppid;
        ex.proc.path = p.path;
        ex.proc.args = p.args;
        set_signing(ex.proc, p.signing);
        evs.push_back(ex);

        const int files = static_cast<int>(rng() % 6);
        for (int f = 0; f < files; ++f) {
            behavior::Event fe;
            fe.type = (rng() % 3 == 0) ? behavior::EventType::FileCreate : behavior::EventType::FileModify;
            fe.time_ms = t += 1;
            fe.proc = ex.proc;
            fe.file_path = "/Users/dev/project/build/obj" + std::to_string(rng() % 500) + ".o";
            evs.push_back(fe);
        }
        if (p.talks_out && rng() % 2 == 0) {
            behavior::Event ne;
            ne.type = behavior::EventType::NetConnect;
            ne.time_ms = t += 2;
            ne.proc = ex.proc;
            ne.remote_ip = "140.82." + std::to_string(rng() % 255) + "." + std::to_string(rng() % 255);
            ne.remote_port = 443;
            evs.push_back(ne);
        }
        if (rng() % 3 != 0) {
            behavior::Event x;
            x.type = behavior::EventType::Exit;
            x.time_ms = t += 1;
            x.proc.pid = pid;
            evs.push_back(x);
        } else {
            live.push_back(pid);
            if (live.size() > 400) live.erase(live.begin() + 4);
        }
    }
    return evs;
}

std::string to_normalized(const behavior::Event& ev) {
    std::string type;
    switch (ev.type) {
        case behavior::EventType::Exec: type = "exec"; break;
        case behavior::EventType::Fork: type = "fork"; break;
        case behavior::EventType::Exit: type = "exit"; break;
        case behavior::EventType::FileCreate: type = "file_create"; break;
        case behavior::EventType::FileModify: type = "file_modify"; break;
        case behavior::EventType::NetConnect: type = "net"; break;
        default: type = "exit"; break;
    }
    std::string s = "{\"type\":\"" + type + "\",\"time_ms\":" + std::to_string(ev.time_ms) +
                    ",\"pid\":" + std::to_string(ev.proc.pid) + ",\"ppid\":" + std::to_string(ev.proc.ppid);
    if (!ev.proc.path.empty()) s += ",\"path\":\"" + ev.proc.path + "\"";
    if (!ev.proc.args.empty()) {
        s += ",\"args\":[";
        for (std::size_t i = 0; i < ev.proc.args.size(); ++i) s += (i ? ",\"" : "\"") + ev.proc.args[i] + "\"";
        s += "]";
    }
    if (!ev.file_path.empty()) s += ",\"file\":\"" + ev.file_path + "\"";
    if (!ev.remote_ip.empty()) s += ",\"remote_ip\":\"" + ev.remote_ip + "\",\"remote_port\":443";
    if (ev.type == behavior::EventType::Fork) s += ",\"child_pid\":" + std::to_string(ev.proc.pid);
    return s + "}";
}

// Roughly the size and shape of a real eslogger exec record (~3 KB): the fields the parser reads plus
// the bulky ones it skips (audit tokens, cdhash, stat blocks, environment).
std::string eslogger_like_exec(int pid, int ppid) {
    const std::string stat =
        R"({"st_blocks":8,"st_blksize":4096,"st_rdev":0,"st_dev":16777234,"st_uid":0,"st_gid":0,"st_ino":1152921500312,)"
        R"("st_birthtimespec":"2026-10-01T00:00:00.000000000Z","st_flags":524320,"st_nlink":1,"st_mode":33261,)"
        R"("st_size":1310224,"st_gen":0,"st_atimespec":"2026-10-01T00:00:00.000000000Z",)"
        R"("st_mtimespec":"2026-10-01T00:00:00.000000000Z","st_ctimespec":"2026-10-01T00:00:00.000000000Z"})";
    const std::string token = R"({"asid":100001,"pidversion":)" + std::to_string(pid * 3) + R"(,"ruid":501,"euid":501,)"
                              R"("rgid":20,"auid":501,"egid":20,"pid":)" + std::to_string(pid) + "}";
    const std::string proc =
        R"({"original_ppid":)" + std::to_string(ppid) + R"(,"is_es_client":false,"start_time":"2026-11-06T00:00:00.000000Z",)"
        R"("cdhash":"3f1c4a7e9b2d8c6f0a1e5b7d9c3f2a4e6b8d0c1f","is_platform_binary":true,"team_id":null,)"
        R"("signing_id":"com.apple.zsh","group_id":)" + std::to_string(pid) + R"(,"session_id":301,"codesigning_flags":570522385,)"
        R"("tty":{"path":"/dev/ttys003","stat":)" + stat + R"(},"executable":{"path":"/bin/zsh","path_truncated":false,"stat":)" +
        stat + R"(},"audit_token":)" + token + R"(,"parent_audit_token":)" + token + R"(,"responsible_audit_token":)" + token +
        R"(,"ppid":)" + std::to_string(ppid) + "}";
    std::string env = "[";
    const char* vars[] = {"PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/Users/dev", "SHELL=/bin/zsh",
                          "TERM=xterm-256color", "LANG=ko_KR.UTF-8", "USER=dev", "TMPDIR=/var/folders/xy/T/",
                          "__CF_USER_TEXT_ENCODING=0x1F5:0x3:0x33", "SSH_AUTH_SOCK=/private/tmp/com.apple.launchd/L",
                          "LOGNAME=dev", "PWD=/Users/dev/project", "OLDPWD=/Users/dev", "SHLVL=2"};
    for (std::size_t i = 0; i < sizeof(vars) / sizeof(vars[0]); ++i) env += (i ? ",\"" : "\"") + std::string(vars[i]) + "\"";
    env += "]";
    return R"({"schema_version":1,"mach_time":123456789012,"event_type":9,"thread":{"thread_id":1234567},)"
           R"("version":7,"seq_num":42,"global_seq_num":4242,"action_type":1,"action":{"result":{"result_type":0,"result":{"auth":0}}},)"
           R"("time":"2026-11-06T00:00:01.123456789Z","process":)" + proc + R"(,"event":{"exec":{"target":)" + proc +
           R"(,"script":null,"cwd":{"path":"/Users/dev/project","path_truncated":false,"stat":)" + stat +
           R"(},"last_fd":3,"image_cputype":16777228,"image_cpusubtype":2,"args":["zsh","-c","git status --porcelain"],)"
           R"("env":)" + env + R"(,"dyld_exec_path":"/bin/zsh","fds":[]}}})";
}

double seconds_since(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
}

}

int run_behavior_bench(int argc, char** argv, int from) {
    int processes = 200000;
    unsigned seed = 1;
    for (int i = from; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--processes" && i + 1 < argc) processes = std::max(1, std::atoi(argv[++i]));
        else if (a == "--seed" && i + 1 < argc) seed = static_cast<unsigned>(std::atoi(argv[++i]));
        else {
            std::fprintf(stderr, "usage: sec-cli behavior-bench [--processes N] [--seed S]\n");
            return 2;
        }
    }

    const std::vector<behavior::Event> evs = synthesize(processes, seed);
    std::printf("events: %zu (from %d processes)\n", evs.size(), processes);

    behavior::Engine engine(behavior::default_ruleset());
    std::size_t alerts = 0;
    const auto t0 = std::chrono::steady_clock::now();
    std::map<std::string, int> by_rule;
    for (const behavior::Event& ev : evs) {
        for (const auto& a : engine.process(ev)) {
            ++alerts;
            std::string k;
            for (const auto& r : a.rule_ids) k += r + " ";
            ++by_rule[k + "| " + a.process_path];
        }
    }
    if (std::getenv("SEC_BENCH_DEBUG")) for (const auto& kv : by_rule) std::printf("%6d %s\n", kv.second, kv.first.c_str());
    const double te = seconds_since(t0);
    std::printf("engine:  %.3f s  %.0f events/s  %.2f us/event  alerts=%zu tree=%zu\n", te,
                static_cast<double>(evs.size()) / te, te * 1e6 / static_cast<double>(evs.size()), alerts,
                engine.tree().size());

    std::vector<std::string> lines;
    lines.reserve(evs.size());
    for (const behavior::Event& ev : evs) lines.push_back(to_normalized(ev));
    std::size_t ok = 0;
    const auto t1 = std::chrono::steady_clock::now();
    for (const std::string& l : lines) ok += behavior::parse_event_line(l).ok() ? 1 : 0;
    const double tp = seconds_since(t1);
    std::printf("parser:  %.3f s  %.0f lines/s  %.2f us/line  ok=%zu  (normalized JSONL)\n", tp,
                static_cast<double>(lines.size()) / tp, tp * 1e6 / static_cast<double>(lines.size()), ok);

    const std::size_t es_count = std::min<std::size_t>(lines.size(), 200000);
    std::vector<std::string> es;
    es.reserve(es_count);
    std::size_t es_bytes = 0;
    for (std::size_t i = 0; i < es_count; ++i) {
        es.push_back(eslogger_like_exec(1000 + static_cast<int>(i % 90000), 300));
        es_bytes += es.back().size();
    }
    std::size_t es_ok = 0;
    const auto t2 = std::chrono::steady_clock::now();
    for (const std::string& l : es) es_ok += behavior::parse_event_line(l).ok() ? 1 : 0;
    const double ts = seconds_since(t2);
    std::printf("eslogger:%.3f s  %.0f lines/s  %.2f us/line  %.0f MB/s  ok=%zu  (avg %zu bytes/line)\n", ts,
                static_cast<double>(es.size()) / ts, ts * 1e6 / static_cast<double>(es.size()),
                static_cast<double>(es_bytes) / ts / 1e6, es_ok, es_bytes / std::max<std::size_t>(1, es.size()));
    return 0;
}
