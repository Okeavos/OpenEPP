#include "behavior/engine.h"

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

std::string lc(const std::string& s) { return util::to_lower(s); }

bool starts_with(const std::string& s, const std::string& p) { return s.compare(0, p.size(), p) == 0; }

bool contains(const std::string& s, const std::string& sub) { return s.find(sub) != std::string::npos; }

bool contains_any(const std::string& s, const std::vector<std::string>& subs) {
    for (const std::string& x : subs) {
        if (contains(s, x)) return true;
    }
    return false;
}

bool prefix_any(const std::string& s, const std::vector<std::string>& ps) {
    for (const std::string& p : ps) {
        if (starts_with(s, p)) return true;
    }
    return false;
}

bool equals_any(const std::string& s, const std::vector<std::string>& xs) {
    return std::find(xs.begin(), xs.end(), s) != xs.end();
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

std::string join_args(const std::vector<std::string>& args) {
    std::string out;
    for (const std::string& a : args) {
        if (!out.empty()) out.push_back(' ');
        out += a;
    }
    return out;
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
                d += " [" + join_args(std::vector<std::string>(ev.proc.args.begin() + 1, ev.proc.args.end())) + "]";
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
    o += ",\"detail\":\"" + json_escape(a.detail) + "\"}";
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
    return o;
}

Engine::Engine(RuleSet rules) : rules_(std::move(rules)) {
    for (std::size_t i = 0; i < rules_.rules.size(); ++i) {
        rule_index_[rules_.rules[i].id] = i;
        rules_by_event_[static_cast<int>(rules_.rules[i].event)].push_back(i);
    }
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
        if (!key.empty() && key[0] == '/') return starts_with(ctx.path, lc(key));
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

std::vector<std::string> Engine::compute_features(const Event& ev, const ProcNode& node, const EvalCtx& ctx) {
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
        default:
            break;
    }
    return f;
}

bool Engine::match_condition(const Rule& rule, const ProcNode& node, const EvalCtx& ctx, std::int64_t now_ms) const {
    const Condition& c = rule.when;

    if (!c.name_any.empty() && !equals_any(node.name, c.name_any)) return false;
    if (!c.name_not_any.empty() && equals_any(node.name, c.name_not_any)) return false;
    if (!c.path_prefix_any.empty() && !prefix_any(ctx.path, c.path_prefix_any)) return false;
    if (!c.path_contains_any.empty() && !contains_any(ctx.path, c.path_contains_any)) return false;
    if (!c.path_not_prefix_any.empty() && prefix_any(ctx.path, c.path_not_prefix_any)) return false;
    if (!c.parent_name_any.empty() && (!ctx.has_parent || !equals_any(ctx.parent_name, c.parent_name_any))) return false;
    if (!c.ancestor_name_any.empty()) {
        bool found = false;
        for (const std::string& a : ctx.ancestors) {
            if (equals_any(a, c.ancestor_name_any)) {
                found = true;
                break;
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

    if (!c.file_path_prefix_any.empty() && !prefix_any(ctx.file_path, c.file_path_prefix_any)) return false;
    if (!c.file_path_contains_any.empty() && !contains_any(ctx.file_path, c.file_path_contains_any)) return false;
    if (!c.file_name_any.empty() && !equals_any(ctx.file_name, c.file_name_any)) return false;
    if (!c.file_ext_any.empty() && !equals_any(ctx.file_ext, c.file_ext_any)) return false;

    if (c.remote_public && ctx.remote_public != *c.remote_public) return false;
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
        const std::int64_t window_ms = 1000LL * (rule.window_s > 0 ? rule.window_s : rules_.tag_window_s);
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

    EvalCtx ctx;
    ctx.path = lc(node->path);
    ctx.cmdline = lc(node->args.empty() ? node->path : join_args(node->args));
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
    const std::vector<const ProcNode*> chain = tree_.chain(node->pid, 16);
    for (std::size_t i = 1; i < chain.size(); ++i) {
        ctx.ancestors.push_back(chain[i]->name);
        if (i == 1) {
            ctx.has_parent = true;
            ctx.parent_name = chain[i]->name;
        }
    }
    ctx.features = compute_features(ev, *node, ctx);

    // Phase 1: rules that do not depend on tags; phase 2: rules that need a tag, so a tag set by a
    // phase-1 rule on this same event is already visible.
    bool fired_any = false;
    bool new_stage = false;
    const std::vector<std::size_t>& candidates = rules_by_event_[static_cast<int>(rule_event_of(ev.type))];
    for (int phase = 1; phase <= 2; ++phase) {
        for (const std::size_t idx : candidates) {
            const Rule& r = rules_.rules[idx];
            if (!r.enabled) continue;
            const bool tag_rule = !r.when.requires_tag_any.empty();
            if ((phase == 2) != tag_rule) continue;
            if (node->hit_ids.count(r.id) != 0) continue;
            if (!match_condition(r, *node, ctx, now)) continue;

            node->hit_ids.insert(r.id);
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
