#include "behavior/engine.h"

#include "behavior/agent_config.h"
#include "behavior/net_util.h"
#include "common/util.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <set>

namespace sec::behavior {

namespace {

constexpr std::int64_t kRecentDownloadMs = 3600LL * 1000;
constexpr std::size_t kMaxWritten = 8192;
constexpr std::size_t kMaxBeaconKeys = 4096;
constexpr std::size_t kBeaconWindow = 12;
constexpr std::size_t kRecentKeep = 512;
constexpr std::size_t kContextLines = 12;
constexpr std::int64_t kContextWindowMs = 900LL * 1000;
constexpr std::size_t kMaxSuspects = 4;

std::string lc(const std::string& s) { return util::to_lower(s); }

bool starts_with(std::string_view s, std::string_view p) { return s.substr(0, p.size()) == p; }

bool contains(std::string_view s, std::string_view sub) { return s.find(sub) != std::string_view::npos; }

bool contains_any(std::string_view s, const std::vector<std::string>& subs) {
    for (const std::string& x : subs) {
        if (contains(s, x)) return true;
    }
    return false;
}

bool prefix_any(std::string_view s, const std::vector<std::string>& ps) {
    for (const std::string& p : ps) {
        if (starts_with(s, p)) return true;
    }
    return false;
}

bool equals_any(std::string_view s, const std::vector<std::string>& xs) {
    for (const std::string& x : xs) {
        if (x == s) return true;
    }
    return false;
}

bool is_build_tool(const std::string& name) {
    static const std::set<std::string> kTools = {
        "clang", "clang++", "cc", "c++", "gcc", "g++", "ld", "ld64", "swift-frontend", "swiftc", "swift-build",
        "rustc", "cargo", "go", "make", "gmake", "ninja", "cmake", "xcodebuild", "ar", "ranlib", "dsymutil",
        "codesign", "install_name_tool", "javac", "mvn", "gradle", "tsc", "lipo", "strip", "libtool", "cpp",
        "swift", "swift-driver", "clangd", "xcrun"};
    return kTools.count(name) != 0;
}

// Tags marking a later attack stage. The first time one appears on a process chain the engine alerts
// again even if the alert level did not rise, so "foothold" and "C2" show up after an intrusion alert.
bool is_stage_tag(const std::string& tag) {
    static const std::set<std::string> kStage = {"persistence", "c2_candidate", "c2_beacon", "c2_ioc",
                                                 "reverse_shell", "credential_access", "priv_esc", "impact"};
    return kStage.count(tag) != 0;
}

RuleEvent rule_event_of(EventType t) {
    switch (t) {
        case EventType::Exec: return RuleEvent::Exec;
        case EventType::NetConnect: return RuleEvent::Net;
        case EventType::DnsQuery: return RuleEvent::Dns;
        default: return RuleEvent::File;
    }
}


std::string json_escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (const char ch : s) {
        const unsigned char c = static_cast<unsigned char>(ch);
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    o += buf;
                } else {
                    o.push_back(ch);
                }
        }
    }
    return o;
}

std::string json_str_array(const std::vector<std::string>& v) {
    std::string o = "[";
    for (std::size_t i = 0; i < v.size(); ++i) {
        if (i != 0) o.push_back(',');
        o += "\"" + json_escape(v[i]) + "\"";
    }
    o.push_back(']');
    return o;
}

bool is_staging_path(const std::string& lower_path) {
    static const char* const kPrefixes[] = {"/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/",
                                            "/users/shared/", "/dev/shm/"};
    for (const char* p : kPrefixes) {
        if (starts_with(lower_path, p)) return true;
    }
    return contains(lower_path, "/downloads/");
}

bool rule_selected(const std::vector<std::string>& patterns, const std::string& id) {
    for (const std::string& p : patterns) {
        if (!p.empty() && p.back() == '*') {
            if (id.compare(0, p.size() - 1, p, 0, p.size() - 1) == 0) return true;
        } else if (p == id) {
            return true;
        }
    }
    return false;
}

std::string pid_label(const ProcNode& n) {
    return (n.name.empty() ? std::string("?") : n.name) + "(" + std::to_string(n.pid) + ")";
}

std::string describe_event(const Event& ev) {
    constexpr std::size_t kMax = 240;
    std::string d;
    switch (ev.type) {
        case EventType::Exec:
            d = "exec " + ev.proc.path;
            if (ev.proc.args.size() > 1) {
                d += " [";
                for (std::size_t i = 1; i < ev.proc.args.size() && d.size() <= kMax; ++i) {
                    if (i != 1) d.push_back(' ');
                    d += ev.proc.args[i];
                }
                d += "]";
            }
            break;
        case EventType::FileCreate: d = "create " + ev.file_path; break;
        case EventType::FileModify: d = "modify " + ev.file_path; break;
        case EventType::FileRename: d = "rename " + ev.file_from + " -> " + ev.file_path; break;
        case EventType::NetConnect:
            d = "connect " + ev.remote_ip + ":" + std::to_string(ev.remote_port);
            if (!ev.remote_host.empty()) d += " (" + ev.remote_host + ")";
            break;
        case EventType::DnsQuery: d = "dns " + ev.dns_name; break;
        default: d = to_string(ev.type); break;
    }
    if (d.size() > kMax) d = d.substr(0, kMax) + "...";
    return d;
}

}

std::string event_summary(const Event& ev) { return describe_event(ev); }

std::string alert_to_json(const Alert& a) {
    std::string o = "{";
    o += "\"time_ms\":" + std::to_string(a.time_ms);
    o += ",\"level\":" + std::to_string(a.level);
    o += ",\"score\":" + std::to_string(a.score);
    o += ",\"pid\":" + std::to_string(a.pid);
    o += ",\"process\":\"" + json_escape(a.process_path) + "\"";
    o += ",\"title\":\"" + json_escape(a.title) + "\"";
    o += ",\"rules\":" + json_str_array(a.rule_ids);
    o += ",\"techniques\":" + json_str_array(a.techniques);
    o += ",\"chain\":" + json_str_array(a.chain);
    o += ",\"detail\":\"" + json_escape(a.detail) + "\"";
    o += ",\"context\":" + json_str_array(a.context);
    o += ",\"files\":" + json_str_array(a.files) + "}";
    return o;
}

std::string alert_to_text(const Alert& a) {
    std::string o = a.level >= 2 ? "[심각] " : "[경고] ";
    o += a.title + "\n";
    o += "  점수: " + std::to_string(a.score) + "  PID: " + std::to_string(a.pid) + "  " + a.process_path + "\n";
    if (!a.chain.empty()) {
        o += "  프로세스 체인: ";
        for (std::size_t i = 0; i < a.chain.size(); ++i) {
            if (i != 0) o += " > ";
            o += a.chain[i];
        }
        o += "\n";
    }
    if (!a.rule_ids.empty()) {
        o += "  규칙: ";
        for (std::size_t i = 0; i < a.rule_ids.size(); ++i) {
            if (i != 0) o += ", ";
            o += a.rule_ids[i];
        }
        o += "\n";
    }
    if (!a.techniques.empty()) {
        o += "  ATT&CK: ";
        for (std::size_t i = 0; i < a.techniques.size(); ++i) {
            if (i != 0) o += ", ";
            o += a.techniques[i];
        }
        o += "\n";
    }
    o += "  이벤트: " + a.detail + "\n";
    if (!a.files.empty()) {
        o += "  관련 파일:\n";
        for (const std::string& f : a.files) o += "    " + f + "\n";
    }
    if (!a.context.empty()) {
        o += "  직전 활동:\n";
        for (const std::string& c : a.context) o += "    " + c + "\n";
    }
    return o;
}

Engine::Engine(RuleSet rules) : rules_(std::move(rules)) {
    for (std::size_t i = 0; i < rules_.rules.size(); ++i) {
        const Rule& r = rules_.rules[i];
        rule_index_[r.id] = i;
        const int e = static_cast<int>(r.event);
        rules_by_event_[e].push_back(i);
        if (r.when.name_any.empty()) {
            indexed_[e].generic.push_back(i);
        } else {
            for (const std::string& n : r.when.name_any) {
                std::vector<std::size_t>& v = indexed_[e].by_name[n];
                if (v.empty() || v.back() != i) v.push_back(i);
            }
        }
    }
    chain_buf_.reserve(16);
}

void Engine::candidates_for(RuleEvent e, const std::string& name, std::vector<std::size_t>& out) const {
    const EventRules& er = indexed_[static_cast<int>(e)];
    out.clear();
    const auto it = er.by_name.find(name);
    if (it == er.by_name.end()) {
        out = er.generic;
        return;
    }
    out.resize(er.generic.size() + it->second.size());
    std::merge(er.generic.begin(), er.generic.end(), it->second.begin(), it->second.end(), out.begin());
}

bool Engine::test_hit(const ProcNode& n, std::size_t idx) const {
    const std::size_t w = idx / 64;
    return w < n.hit_bits.size() && (n.hit_bits[w] >> (idx % 64) & 1u) != 0;
}

void Engine::set_hit(ProcNode& n, std::size_t idx) const {
    const std::size_t w = idx / 64;
    if (n.hit_bits.size() <= w) n.hit_bits.resize(w + 1, 0);
    n.hit_bits[w] |= std::uint64_t{1} << (idx % 64);
}

void Engine::note_file_write(const Event& ev, const ProcNode& node) {
    if (ev.file_path.empty()) return;
    written_[ev.file_path] = Written{ev.time_ms, node.name};
    if (written_.size() <= kMaxWritten) return;
    for (auto it = written_.begin(); it != written_.end();) {
        if (ev.time_ms - it->second.time_ms > kRecentDownloadMs) it = written_.erase(it);
        else ++it;
    }
    if (written_.size() > kMaxWritten) written_.clear();
}

bool Engine::beacon_check(const Event& ev) {
    if (ev.proc.pid <= 0 || ev.remote_ip.empty() || net::is_private_or_local(ev.remote_ip)) return false;
    if (beacons_.size() > kMaxBeaconKeys) beacons_.clear();

    const std::string key = std::to_string(ev.proc.pid) + "|" + ev.remote_ip + ":" + std::to_string(ev.remote_port);
    std::deque<std::int64_t>& times = beacons_[key];
    times.push_back(ev.time_ms);
    while (times.size() > kBeaconWindow) times.pop_front();
    if (times.size() < 6) return false;

    std::vector<double> gaps;
    for (std::size_t i = 1; i < times.size(); ++i) gaps.push_back(static_cast<double>(times[i] - times[i - 1]));
    double mean = 0;
    for (const double g : gaps) mean += g;
    mean /= static_cast<double>(gaps.size());
    if (mean < 5000.0) return false;
    double var = 0;
    for (const double g : gaps) var += (g - mean) * (g - mean);
    var /= static_cast<double>(gaps.size());
    return std::sqrt(var) / mean <= 0.2;
}

bool Engine::ioc_match(const Event& ev) const {
    if (ev.type == EventType::NetConnect) {
        for (const std::string& spec : ioc_.ips) {
            if (!ev.remote_ip.empty() && net::ip_matches(ev.remote_ip, spec)) return true;
        }
    }
    const std::string& host = ev.type == EventType::DnsQuery ? ev.dns_name : ev.remote_host;
    if (!host.empty()) {
        for (const std::string& pat : ioc_.hosts) {
            if (net::host_matches(host, pat)) return true;
        }
    }
    return false;
}

bool Engine::egress_violation(const Event& ev, const ProcNode& node, const EvalCtx& ctx) const {
    const EgressPolicy& pol = rules_.egress;
    if (!pol.enabled || ev.remote_ip.empty() || net::is_private_or_local(ev.remote_ip)) return false;

    auto process_matches = [&](const std::string& key) {
        if (!key.empty() && key[0] == '/') return starts_with(ctx.path, std::string_view(lc(key)));
        return key == node.name;
    };

    if (!pol.applies_to.empty()) {
        bool subject = false;
        for (const std::string& k : pol.applies_to) {
            if (process_matches(k)) {
                subject = true;
                break;
            }
        }
        if (!subject) return false;
    }

    auto allowed_by = [&](const std::vector<std::string>& list) {
        for (const std::string& spec : list) {
            std::uint32_t tmp = 0;
            const bool is_ip_spec = spec.find('/') != std::string::npos || net::parse_ipv4(spec, tmp);
            if (is_ip_spec) {
                if (net::ip_matches(ev.remote_ip, spec)) return true;
            } else if (!ev.remote_host.empty() && net::host_matches(ev.remote_host, spec)) {
                return true;
            }
        }
        return false;
    };

    if (allowed_by(pol.allow)) return false;
    for (const auto& kv : pol.per_process) {
        if (process_matches(kv.first) && allowed_by(kv.second)) return false;
    }
    return true;
}

std::vector<std::string> Engine::compute_features(const Event& ev, const ProcNode& node, EvalCtx& ctx) {
    std::vector<std::string> f;
    switch (ev.type) {
        case EventType::Exec: {
            const auto it = written_.find(node.path);
            if (it != written_.end() && ev.time_ms - it->second.time_ms <= kRecentDownloadMs &&
                ev.time_ms >= it->second.time_ms && !is_build_tool(it->second.writer)) {
                f.push_back("recent_download_exec");
            }
            break;
        }
        case EventType::NetConnect:
            if (beacon_check(ev)) f.push_back("beaconing");
            if (ioc_match(ev)) f.push_back("ioc_match");
            if (!ev.remote_host.empty() && net::looks_like_dga(ev.remote_host)) f.push_back("dga_like");
            if (egress_violation(ev, node, ctx)) f.push_back("egress_violation");
            break;
        case EventType::DnsQuery:
            if (ioc_match(ev)) f.push_back("ioc_match");
            if (net::looks_like_dga(ev.dns_name)) f.push_back("dga_like");
            if (net::looks_like_tunnel(ev.dns_name)) f.push_back("tunnel_like");
            break;
        case EventType::FileCreate:
        case EventType::FileModify:
        case EventType::FileRename:
            if (!ctx.file_path.empty() && is_agent_config_path(ctx.file_path)) {
                f.push_back("ai_agent_config");
                if (inspector_) {
                    ctx.findings = inspector_(ev.file_path);
                    if (!ctx.findings.empty()) f.push_back("agent_config_suspicious");
                }
            }
            break;
        default:
            break;
    }
    return f;
}

bool Engine::match_cond(const Condition& c, int rule_window_s, const ProcNode& node, const EvalCtx& ctx,
                        std::int64_t now_ms) const {

    if (!c.name_any.empty() && !equals_any(node.name, c.name_any)) return false;
    if (!c.name_not_any.empty() && equals_any(node.name, c.name_not_any)) return false;
    if (!c.path_prefix_any.empty() && !prefix_any(ctx.path, c.path_prefix_any)) return false;
    if (!c.path_contains_any.empty() && !contains_any(ctx.path, c.path_contains_any)) return false;
    if (!c.path_not_prefix_any.empty() && prefix_any(ctx.path, c.path_not_prefix_any)) return false;
    if (!c.parent_name_any.empty()) {
        if (ctx.chain == nullptr || ctx.chain->size() < 2 || !equals_any((*ctx.chain)[1]->name, c.parent_name_any)) {
            return false;
        }
    }
    if (!c.ancestor_name_any.empty()) {
        bool found = false;
        if (ctx.chain != nullptr) {
            for (std::size_t i = 1; i < ctx.chain->size() && !found; ++i) {
                found = equals_any((*ctx.chain)[i]->name, c.ancestor_name_any);
            }
        }
        if (!found) return false;
    }
    if (!c.args_contains_any.empty() && !contains_any(ctx.cmdline, c.args_contains_any)) return false;
    for (const auto& group : c.args_all_of_any) {
        if (!contains_any(ctx.cmdline, group)) return false;
    }
    if (c.unsigned_process && node.is_unsigned() != *c.unsigned_process) return false;
    if (c.platform_binary && node.platform_binary != *c.platform_binary) return false;
    if (!c.team_id_any.empty() && !equals_any(ctx.team_id, c.team_id_any)) return false;
    if (!c.signing_id_any.empty() && !equals_any(ctx.signing_id, c.signing_id_any)) return false;
    if (!c.env_contains_any.empty() && !contains_any(ctx.env, c.env_contains_any)) return false;

    if (!c.file_path_prefix_any.empty() && !prefix_any(ctx.file_path, c.file_path_prefix_any)) return false;
    if (!c.file_path_contains_any.empty() && !contains_any(ctx.file_path, c.file_path_contains_any)) return false;
    if (!c.file_name_any.empty() && !equals_any(ctx.file_name, c.file_name_any)) return false;
    if (!c.file_ext_any.empty() && !equals_any(ctx.file_ext, c.file_ext_any)) return false;

    if (c.remote_public && ctx.remote_public != *c.remote_public) return false;
    if (!c.remote_ip_any.empty()) {
        bool ok = false;
        for (const std::string& spec : c.remote_ip_any) {
            if (!ctx.remote_ip.empty() && net::ip_matches(ctx.remote_ip, spec)) {
                ok = true;
                break;
            }
        }
        if (!ok) return false;
    }
    if (!c.remote_host_any.empty()) {
        bool ok = false;
        for (const std::string& pat : c.remote_host_any) {
            if (!ctx.host.empty() && net::host_matches(ctx.host, pat)) {
                ok = true;
                break;
            }
        }
        if (!ok) return false;
    }
    if (!c.port_any.empty() && std::find(c.port_any.begin(), c.port_any.end(), ctx.remote_port) == c.port_any.end()) {
        return false;
    }
    if (!c.port_not_any.empty() &&
        std::find(c.port_not_any.begin(), c.port_not_any.end(), ctx.remote_port) != c.port_not_any.end()) {
        return false;
    }

    if (!c.requires_feature_any.empty()) {
        bool ok = false;
        for (const std::string& f : c.requires_feature_any) {
            if (std::find(ctx.features.begin(), ctx.features.end(), f) != ctx.features.end()) {
                ok = true;
                break;
            }
        }
        if (!ok) return false;
    }
    if (!c.requires_tag_any.empty()) {
        const std::int64_t window_ms = 1000LL * (rule_window_s > 0 ? rule_window_s : rules_.tag_window_s);
        bool ok = false;
        for (const std::string& t : c.requires_tag_any) {
            const auto it = node.tags.find(t);
            if (it != node.tags.end() && now_ms - it->second <= window_ms) {
                ok = true;
                break;
            }
        }
        if (!ok) return false;
    }
    return true;
}

bool Engine::is_allowed(const Rule& rule, const ProcNode& node, const EvalCtx& ctx, std::int64_t now_ms) const {
    for (const AllowEntry& e : rules_.allowlist) {
        if (e.event && *e.event != rule.event) continue;
        if (!e.rules.empty() && !rule_selected(e.rules, rule.id)) continue;
        if (!match_cond(e.when, 0, node, ctx, now_ms)) continue;
        return true;
    }
    return false;
}

std::vector<std::string> Engine::build_context(const std::vector<const ProcNode*>& chain, std::int64_t now_ms) const {
    std::set<int> pids;
    for (const ProcNode* n : chain) {
        if (n->pid > 1) pids.insert(n->pid);  // launchd's children are every daemon on the system
    }

    std::vector<const Recent*> picked;
    for (auto it = recent_.rbegin(); it != recent_.rend() && picked.size() < kContextLines; ++it) {
        if (now_ms - it->time_ms > kContextWindowMs) break;
        if (pids.count(it->pid) != 0 || pids.count(it->ppid) != 0) picked.push_back(&*it);
    }
    std::vector<std::string> out;
    for (auto it = picked.rbegin(); it != picked.rend(); ++it) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "T%+.1fs", static_cast<double>((*it)->time_ms - now_ms) / 1000.0);
        out.push_back(std::string(buf) + "  " + (*it)->text);
    }
    return out;
}

void Engine::seed_process(const ProcessRef& ref, std::int64_t time_ms) {
    if (ref.pid <= 0) return;
    tree_.seed(ref, time_ms);
    ++seeded_;
}

std::vector<Alert> Engine::process(const Event& ev) {
    std::vector<Alert> out;
    ++events_;
    if ((events_ & 0x3FFF) == 0) tree_.gc(ev.time_ms);

    const std::int64_t now = ev.time_ms;
    ProcNode* node = nullptr;

    switch (ev.type) {
        case EventType::Fork: {
            if (ev.proc.pid <= 0) return out;
            ProcNode& n = tree_.on_fork(ev.proc, now);
            if (n.path.empty()) {
                if (const ProcNode* parent = tree_.find(n.ppid)) {
                    n.path = parent->path;
                    n.name = parent->name;
                    n.args = parent->args;
                    n.signing_id = parent->signing_id;
                    n.team_id = parent->team_id;
                    n.platform_binary = parent->platform_binary;
                    n.sig_known = parent->sig_known;
                    n.env = parent->env;
                    n.lpath = parent->lpath;
                    n.lcmd = parent->lcmd;
                    n.lteam = parent->lteam;
                    n.lsigning = parent->lsigning;
                    n.lenv = parent->lenv;
                }
            }
            return out;
        }
        case EventType::Exit: {
            tree_.on_exit(ev.proc.pid, now);
            const std::string prefix = std::to_string(ev.proc.pid) + "|";
            auto it = beacons_.lower_bound(prefix);
            while (it != beacons_.end() && starts_with(it->first, prefix)) it = beacons_.erase(it);
            return out;
        }
        case EventType::Exec:
            if (ev.proc.pid <= 0) return out;
            node = &tree_.on_exec(ev.proc, now);
            break;
        default:
            if (ev.proc.pid <= 0) return out;
            node = &tree_.upsert_actor(ev.proc, now);
            break;
    }

    if (ev.type == EventType::FileCreate || ev.type == EventType::FileModify || ev.type == EventType::FileRename) {
        note_file_write(ev, *node);
    }

    {
        Recent r{now, node->pid, node->ppid, std::string()};
        const std::string desc = describe_event(ev);
        r.text.reserve(node->name.size() + desc.size() + 16);
        r.text += node->name.empty() ? std::string_view("?") : std::string_view(node->name);
        r.text += '(';
        r.text += std::to_string(node->pid);
        r.text += ")  ";
        r.text += desc;
        if (recent_.size() >= kRecentKeep) recent_.pop_front();
        recent_.push_back(std::move(r));
    }

    EvalCtx ctx;
    ctx.path = node->lpath;
    ctx.team_id = node->lteam;
    ctx.signing_id = node->lsigning;
    ctx.env = node->lenv;
    ctx.cmdline = node->lcmd;
    if (ev.type == EventType::NetConnect || ev.type == EventType::DnsQuery) {
        ctx.remote_ip = ev.remote_ip;
        ctx.host = lc(ev.type == EventType::DnsQuery ? ev.dns_name : ev.remote_host);
    }
    ctx.file_path = lc(ev.file_path);
    if (!ctx.file_path.empty()) {
        const std::size_t slash = ctx.file_path.find_last_of('/');
        ctx.file_name = slash == std::string::npos ? ctx.file_path : ctx.file_path.substr(slash + 1);
        const std::size_t dot = ctx.file_name.find_last_of('.');
        if (dot != std::string::npos && dot + 1 < ctx.file_name.size()) ctx.file_ext = ctx.file_name.substr(dot + 1);
    }
    if (ev.type == EventType::NetConnect) {
        ctx.remote_port = ev.remote_port;
        ctx.remote_public = !ev.remote_ip.empty() && !net::is_private_or_local(ev.remote_ip);
    }
    tree_.chain_into(node->pid, 16, chain_buf_);
    const std::vector<const ProcNode*>& chain = chain_buf_;
    ctx.chain = &chain;
    ctx.features = compute_features(ev, *node, ctx);

    // Phase 1: rules that do not depend on tags; phase 2: rules that need a tag, so a tag set by a
    // phase-1 rule on this same event is already visible.
    bool fired_any = false;
    bool new_stage = false;
    candidates_for(rule_event_of(ev.type), node->name, cand_buf_);
    const std::vector<std::size_t>& candidates = cand_buf_;
    for (int phase = 1; phase <= 2; ++phase) {
        for (const std::size_t idx : candidates) {
            const Rule& r = rules_.rules[idx];
            if (!r.enabled) continue;
            const bool tag_rule = !r.when.requires_tag_any.empty();
            if ((phase == 2) != tag_rule) continue;
            if (test_hit(*node, idx)) continue;
            if (!match_cond(r.when, r.window_s, *node, ctx, now)) continue;
            if (!rules_.allowlist.empty() && is_allowed(r, *node, ctx, now)) {
                ++suppressed_;
                continue;
            }

            node->hit_ids.insert(r.id);
            set_hit(*node, idx);
            node->hits.push_back(r.id);
            node->score += r.score;
            if (!r.tag.empty()) {
                if (is_stage_tag(r.tag) && node->tags.count(r.tag) == 0) new_stage = true;
                node->tags[r.tag] = now;
            }
            fired_any = true;
        }
    }
    if (!fired_any) return out;

    const int level = node->score >= rules_.critical_threshold ? 2 : (node->score >= rules_.warn_threshold ? 1 : 0);
    if (level == 0 || (level <= node->alert_level && !new_stage)) return out;
    if (level > node->alert_level) node->alert_level = level;

    Alert a;
    a.time_ms = now;
    a.level = level;
    a.score = node->score;
    a.pid = node->pid;
    a.process_path = node->path;
    a.detail = describe_event(ev);
    if (!ctx.findings.empty()) {
        a.detail += " | 설정 검사:";
        for (std::size_t i = 0; i < ctx.findings.size(); ++i) a.detail += (i == 0 ? " " : "; ") + ctx.findings[i];
    }

    std::set<std::string> seen_rules;
    std::set<std::string> seen_tech;
    std::vector<std::string> titles;
    for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
        a.chain.push_back(pid_label(**it));
        for (const std::string& id : (*it)->hits) {
            if (!seen_rules.insert(id).second) continue;
            a.rule_ids.push_back(id);
            const auto ri = rule_index_.find(id);
            if (ri == rule_index_.end()) continue;
            const Rule& r = rules_.rules[ri->second];
            titles.push_back(r.title);
            if (!r.technique.empty() && seen_tech.insert(r.technique).second) a.techniques.push_back(r.technique);
        }
    }
    a.context = build_context(chain, now);
    for (std::size_t i = 0; i < chain.size() && i < 6 && a.suspect_paths.size() < kMaxSuspects; ++i) {
        const std::string& p = chain[i]->path;
        if (p.empty() || p[0] != '/') continue;
        if (!chain[i]->is_unsigned() && !is_staging_path(lc(p))) continue;
        if (std::find(a.suspect_paths.begin(), a.suspect_paths.end(), p) == a.suspect_paths.end()) {
            a.suspect_paths.push_back(p);
        }
    }
    if (rule_event_of(ev.type) == RuleEvent::File && !ev.file_path.empty() && ev.file_path[0] == '/' &&
        a.suspect_paths.size() < kMaxSuspects && is_staging_path(lc(ev.file_path)) &&
        std::find(a.suspect_paths.begin(), a.suspect_paths.end(), ev.file_path) == a.suspect_paths.end()) {
        a.suspect_paths.push_back(ev.file_path);
    }

    constexpr std::size_t kMaxTitles = 4;
    const std::size_t from = titles.size() > kMaxTitles ? titles.size() - kMaxTitles : 0;
    if (from > 0) a.title = "… → ";
    for (std::size_t i = from; i < titles.size(); ++i) {
        if (i != from) a.title += " → ";
        a.title += titles[i];
    }
    out.push_back(std::move(a));
    return out;
}

}
