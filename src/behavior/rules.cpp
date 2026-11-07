#include "behavior/rules.h"

#include "common/util.h"

#include <set>

namespace sec::behavior {

namespace {

using json::Value;

struct Ctx {
    std::string* error;
    bool failed = false;

    void fail(const std::string& msg) {
        if (!failed && error != nullptr) *error = msg;
        failed = true;
    }
};

bool check_keys(const Value& obj, const std::set<std::string>& allowed, const std::string& where, Ctx& ctx) {
    for (const std::string& k : obj.keys()) {
        if (allowed.count(k) == 0) {
            ctx.fail(where + ": unknown key '" + k + "'");
            return false;
        }
    }
    return true;
}

bool read_string_list(const Value& v, const std::string& where, std::vector<std::string>& out, bool lower, Ctx& ctx) {
    if (!v.is_array()) {
        ctx.fail(where + ": expected an array of strings");
        return false;
    }
    for (const Value& e : v.items()) {
        if (!e.is_string()) {
            ctx.fail(where + ": expected an array of strings");
            return false;
        }
        out.push_back(lower ? util::to_lower(e.as_string()) : e.as_string());
    }
    return true;
}

bool read_int_list(const Value& v, const std::string& where, std::vector<int>& out, Ctx& ctx) {
    if (!v.is_array()) {
        ctx.fail(where + ": expected an array of integers");
        return false;
    }
    for (const Value& e : v.items()) {
        if (!e.is_number() || e.as_int() < 0 || e.as_int() > 65535) {
            ctx.fail(where + ": expected port numbers (0-65535)");
            return false;
        }
        out.push_back(static_cast<int>(e.as_int()));
    }
    return true;
}

bool read_bool(const Value& v, const std::string& where, std::optional<bool>& out, Ctx& ctx) {
    if (!v.is_bool()) {
        ctx.fail(where + ": expected true/false");
        return false;
    }
    out = v.as_bool();
    return true;
}

bool parse_condition(const Value& w, const std::string& where, Condition& c, Ctx& ctx) {
    if (!w.is_object()) {
        ctx.fail(where + ": 'when' must be an object");
        return false;
    }
    static const std::set<std::string> kKeys = {
        "name_any", "name_not_any", "path_prefix_any", "path_contains_any", "path_not_prefix_any",
        "parent_name_any", "ancestor_name_any", "args_contains_any", "args_all_of_any", "unsigned_process",
        "platform_binary", "file_path_prefix_any", "file_path_contains_any", "file_name_any", "file_ext_any",
        "port_any", "port_not_any", "remote_public", "requires_tag_any", "requires_feature_any", "team_id_any",
        "signing_id_any", "env_contains_any", "remote_ip_any", "remote_host_any"};
    if (!check_keys(w, kKeys, where, ctx)) return false;

    for (std::size_t i = 0; i < w.keys().size(); ++i) {
        const std::string& k = w.keys()[i];
        const Value& v = w.items()[i];
        const std::string at = where + "." + k;
        bool ok = true;
        if (k == "name_any") ok = read_string_list(v, at, c.name_any, true, ctx);
        else if (k == "name_not_any") ok = read_string_list(v, at, c.name_not_any, true, ctx);
        else if (k == "path_prefix_any") ok = read_string_list(v, at, c.path_prefix_any, true, ctx);
        else if (k == "path_contains_any") ok = read_string_list(v, at, c.path_contains_any, true, ctx);
        else if (k == "path_not_prefix_any") ok = read_string_list(v, at, c.path_not_prefix_any, true, ctx);
        else if (k == "parent_name_any") ok = read_string_list(v, at, c.parent_name_any, true, ctx);
        else if (k == "ancestor_name_any") ok = read_string_list(v, at, c.ancestor_name_any, true, ctx);
        else if (k == "args_contains_any") ok = read_string_list(v, at, c.args_contains_any, true, ctx);
        else if (k == "args_all_of_any") {
            if (!v.is_array()) {
                ctx.fail(at + ": expected an array of arrays of strings");
                return false;
            }
            for (const Value& g : v.items()) {
                std::vector<std::string> group;
                if (!read_string_list(g, at, group, true, ctx)) return false;
                if (group.empty()) {
                    ctx.fail(at + ": empty group");
                    return false;
                }
                c.args_all_of_any.push_back(std::move(group));
            }
        } else if (k == "unsigned_process") ok = read_bool(v, at, c.unsigned_process, ctx);
        else if (k == "platform_binary") ok = read_bool(v, at, c.platform_binary, ctx);
        else if (k == "file_path_prefix_any") ok = read_string_list(v, at, c.file_path_prefix_any, true, ctx);
        else if (k == "file_path_contains_any") ok = read_string_list(v, at, c.file_path_contains_any, true, ctx);
        else if (k == "file_name_any") ok = read_string_list(v, at, c.file_name_any, true, ctx);
        else if (k == "file_ext_any") ok = read_string_list(v, at, c.file_ext_any, true, ctx);
        else if (k == "port_any") ok = read_int_list(v, at, c.port_any, ctx);
        else if (k == "port_not_any") ok = read_int_list(v, at, c.port_not_any, ctx);
        else if (k == "remote_public") ok = read_bool(v, at, c.remote_public, ctx);
        else if (k == "requires_tag_any") ok = read_string_list(v, at, c.requires_tag_any, false, ctx);
        else if (k == "requires_feature_any") ok = read_string_list(v, at, c.requires_feature_any, false, ctx);
        else if (k == "team_id_any") ok = read_string_list(v, at, c.team_id_any, true, ctx);
        else if (k == "signing_id_any") ok = read_string_list(v, at, c.signing_id_any, true, ctx);
        else if (k == "env_contains_any") ok = read_string_list(v, at, c.env_contains_any, true, ctx);
        else if (k == "remote_ip_any") ok = read_string_list(v, at, c.remote_ip_any, false, ctx);
        else if (k == "remote_host_any") ok = read_string_list(v, at, c.remote_host_any, true, ctx);
        if (!ok) return false;
    }
    return true;
}

bool parse_rule(const Value& r, std::size_t index, Rule& rule, Ctx& ctx) {
    const std::string where = "rules[" + std::to_string(index) + "]";
    if (!r.is_object()) {
        ctx.fail(where + ": expected an object");
        return false;
    }
    static const std::set<std::string> kKeys = {"id",     "title",   "event",   "score", "tag",
                                                "technique", "enabled", "window_s", "when"};
    if (!check_keys(r, kKeys, where, ctx)) return false;

    if (!r["id"].is_string() || r["id"].as_string().empty()) {
        ctx.fail(where + ": 'id' is required");
        return false;
    }
    rule.id = r["id"].as_string();
    const std::string at = "rule '" + rule.id + "'";

    if (!r["title"].is_string() || r["title"].as_string().empty()) {
        ctx.fail(at + ": 'title' is required");
        return false;
    }
    rule.title = r["title"].as_string();

    const std::string ev = r["event"].as_string();
    if (ev == "exec") rule.event = RuleEvent::Exec;
    else if (ev == "file") rule.event = RuleEvent::File;
    else if (ev == "net") rule.event = RuleEvent::Net;
    else if (ev == "dns") rule.event = RuleEvent::Dns;
    else {
        ctx.fail(at + ": 'event' must be exec|file|net|dns");
        return false;
    }

    if (!r["score"].is_number() || r["score"].as_int() < 0 || r["score"].as_int() > 1000) {
        ctx.fail(at + ": 'score' must be a number 0..1000");
        return false;
    }
    rule.score = static_cast<int>(r["score"].as_int());

    if (const Value* t = r.find("tag")) {
        if (!t->is_string()) {
            ctx.fail(at + ": 'tag' must be a string");
            return false;
        }
        rule.tag = t->as_string();
    }
    if (const Value* t = r.find("technique")) {
        if (!t->is_string()) {
            ctx.fail(at + ": 'technique' must be a string");
            return false;
        }
        rule.technique = t->as_string();
    }
    if (const Value* t = r.find("enabled")) {
        if (!t->is_bool()) {
            ctx.fail(at + ": 'enabled' must be true/false");
            return false;
        }
        rule.enabled = t->as_bool();
    }
    if (const Value* t = r.find("window_s")) {
        if (!t->is_number() || t->as_int() < 0) {
            ctx.fail(at + ": 'window_s' must be a non-negative number");
            return false;
        }
        rule.window_s = static_cast<int>(t->as_int());
    }
    if (const Value* w = r.find("when")) {
        if (!parse_condition(*w, at + ".when", rule.when, ctx)) return false;
    }
    return true;
}

bool condition_is_empty(const Condition& c) {
    return c.name_any.empty() && c.name_not_any.empty() && c.path_prefix_any.empty() && c.path_contains_any.empty() &&
           c.path_not_prefix_any.empty() && c.parent_name_any.empty() && c.ancestor_name_any.empty() &&
           c.args_contains_any.empty() && c.args_all_of_any.empty() && !c.unsigned_process && !c.platform_binary &&
           c.team_id_any.empty() && c.signing_id_any.empty() && c.env_contains_any.empty() &&
           c.file_path_prefix_any.empty() && c.file_path_contains_any.empty() && c.file_name_any.empty() &&
           c.file_ext_any.empty() && c.port_any.empty() && c.port_not_any.empty() && !c.remote_public &&
           c.remote_ip_any.empty() && c.remote_host_any.empty() && c.requires_tag_any.empty() &&
           c.requires_feature_any.empty();
}

bool parse_allow_entry(const Value& r, std::size_t index, AllowEntry& entry, Ctx& ctx) {
    const std::string where = "allowlist[" + std::to_string(index) + "]";
    if (!r.is_object()) {
        ctx.fail(where + ": expected an object");
        return false;
    }
    static const std::set<std::string> kKeys = {"id", "note", "rules", "event", "when"};
    if (!check_keys(r, kKeys, where, ctx)) return false;

    if (const Value* v = r.find("id")) {
        if (!v->is_string()) {
            ctx.fail(where + ".id: expected a string");
            return false;
        }
        entry.id = v->as_string();
    }
    if (entry.id.empty()) entry.id = "allow#" + std::to_string(index + 1);
    const std::string at = "allowlist '" + entry.id + "'";
    if (const Value* v = r.find("note")) {
        if (!v->is_string()) {
            ctx.fail(at + ".note: expected a string");
            return false;
        }
        entry.note = v->as_string();
    }
    if (const Value* v = r.find("rules")) {
        if (!read_string_list(*v, at + ".rules", entry.rules, false, ctx)) return false;
    }
    if (const Value* v = r.find("event")) {
        const std::string ev = v->as_string();
        if (ev == "exec") entry.event = RuleEvent::Exec;
        else if (ev == "file") entry.event = RuleEvent::File;
        else if (ev == "net") entry.event = RuleEvent::Net;
        else if (ev == "dns") entry.event = RuleEvent::Dns;
        else {
            ctx.fail(at + ": 'event' must be exec|file|net|dns");
            return false;
        }
    }
    if (const Value* w = r.find("when")) {
        if (!parse_condition(*w, at + ".when", entry.when, ctx)) return false;
        if (!entry.when.requires_tag_any.empty() || !entry.when.requires_feature_any.empty()) {
            ctx.fail(at + ".when: requires_tag_any / requires_feature_any are not allowed in an allowlist");
            return false;
        }
    }
    if (entry.rules.empty() && !entry.event && condition_is_empty(entry.when)) {
        ctx.fail(at + ": entry would allow everything; give 'rules', 'event' or 'when'");
        return false;
    }
    return true;
}

bool parse_egress(const Value& e, EgressPolicy& out, Ctx& ctx) {
    if (!e.is_object()) {
        ctx.fail("egress: expected an object");
        return false;
    }
    static const std::set<std::string> kKeys = {"enabled", "applies_to", "allow", "per_process"};
    if (!check_keys(e, kKeys, "egress", ctx)) return false;
    if (const Value* v = e.find("enabled")) {
        if (!v->is_bool()) {
            ctx.fail("egress.enabled: expected true/false");
            return false;
        }
        out.enabled = v->as_bool();
    }
    if (const Value* v = e.find("applies_to")) {
        if (!read_string_list(*v, "egress.applies_to", out.applies_to, true, ctx)) return false;
    }
    if (const Value* v = e.find("allow")) {
        if (!read_string_list(*v, "egress.allow", out.allow, false, ctx)) return false;
    }
    if (const Value* v = e.find("per_process")) {
        if (!v->is_object()) {
            ctx.fail("egress.per_process: expected an object");
            return false;
        }
        for (std::size_t i = 0; i < v->keys().size(); ++i) {
            std::vector<std::string> list;
            if (!read_string_list(v->items()[i], "egress.per_process." + v->keys()[i], list, false, ctx)) return false;
            out.per_process[util::to_lower(v->keys()[i])] = std::move(list);
        }
    }
    return true;
}

}

bool load_ruleset(const json::Value& doc, RuleSet& out, std::string* error) {
    Ctx ctx{error};
    RuleSet rs;
    if (!doc.is_object()) {
        ctx.fail("rule file must be a JSON object");
        return false;
    }
    static const std::set<std::string> kKeys = {"thresholds", "tag_window_s", "egress", "rules", "allowlist"};
    if (!check_keys(doc, kKeys, "root", ctx)) return false;

    if (const Value* t = doc.find("thresholds")) {
        if (!t->is_object()) {
            ctx.fail("thresholds: expected an object");
            return false;
        }
        static const std::set<std::string> kT = {"warn", "critical"};
        if (!check_keys(*t, kT, "thresholds", ctx)) return false;
        if (const Value* v = t->find("warn")) {
            if (!v->is_number() || v->as_int() <= 0) {
                ctx.fail("thresholds.warn: expected a positive number");
                return false;
            }
            rs.warn_threshold = static_cast<int>(v->as_int());
        }
        if (const Value* v = t->find("critical")) {
            if (!v->is_number() || v->as_int() <= 0) {
                ctx.fail("thresholds.critical: expected a positive number");
                return false;
            }
            rs.critical_threshold = static_cast<int>(v->as_int());
        }
        if (rs.critical_threshold < rs.warn_threshold) {
            ctx.fail("thresholds: critical must be >= warn");
            return false;
        }
    }
    if (const Value* v = doc.find("tag_window_s")) {
        if (!v->is_number() || v->as_int() <= 0) {
            ctx.fail("tag_window_s: expected a positive number");
            return false;
        }
        rs.tag_window_s = static_cast<int>(v->as_int());
    }
    if (const Value* v = doc.find("egress")) {
        if (!parse_egress(*v, rs.egress, ctx)) return false;
    }
    if (const Value* rules = doc.find("rules")) {
        if (!rules->is_array()) {
            ctx.fail("rules: expected an array");
            return false;
        }
        std::set<std::string> ids;
        for (std::size_t i = 0; i < rules->items().size(); ++i) {
            Rule r;
            if (!parse_rule(rules->items()[i], i, r, ctx)) return false;
            if (!ids.insert(r.id).second) {
                ctx.fail("duplicate rule id '" + r.id + "'");
                return false;
            }
            rs.rules.push_back(std::move(r));
        }
    }
    if (const Value* al = doc.find("allowlist")) {
        if (!al->is_array()) {
            ctx.fail("allowlist: expected an array");
            return false;
        }
        std::set<std::string> ids;
        for (std::size_t i = 0; i < al->items().size(); ++i) {
            AllowEntry e;
            if (!parse_allow_entry(al->items()[i], i, e, ctx)) return false;
            if (!ids.insert(e.id).second) {
                ctx.fail("duplicate allowlist id '" + e.id + "'");
                return false;
            }
            rs.allowlist.push_back(std::move(e));
        }
    }
    out = std::move(rs);
    return true;
}

bool load_ruleset_text(std::string_view text, RuleSet& out, std::string* error) {
    std::string perr;
    const auto doc = json::parse(text, &perr);
    if (!doc) {
        if (error != nullptr) *error = "JSON parse error: " + perr;
        return false;
    }
    return load_ruleset(*doc, out, error);
}

bool load_ioc_text(std::string_view text, IocSet& out, std::string* error) {
    std::string perr;
    const auto doc = json::parse(text, &perr);
    if (!doc) {
        if (error != nullptr) *error = "JSON parse error: " + perr;
        return false;
    }
    if (!doc->is_object()) {
        if (error != nullptr) *error = "IOC file must be a JSON object";
        return false;
    }
    Ctx ctx{error};
    static const std::set<std::string> kKeys = {"ips", "hosts"};
    if (!check_keys(*doc, kKeys, "ioc", ctx)) return false;
    IocSet ioc;
    if (const Value* v = doc->find("ips")) {
        if (!read_string_list(*v, "ioc.ips", ioc.ips, false, ctx)) return false;
    }
    if (const Value* v = doc->find("hosts")) {
        if (!read_string_list(*v, "ioc.hosts", ioc.hosts, false, ctx)) return false;
    }
    out = std::move(ioc);
    return true;
}

void merge_ruleset(RuleSet& base, const RuleSet& overlay) {
    for (const Rule& r : overlay.rules) {
        bool replaced = false;
        for (Rule& b : base.rules) {
            if (b.id == r.id) {
                b = r;
                replaced = true;
                break;
            }
        }
        if (!replaced) base.rules.push_back(r);
    }
    base.warn_threshold = overlay.warn_threshold;
    base.critical_threshold = overlay.critical_threshold;
    base.tag_window_s = overlay.tag_window_s;
    base.egress = overlay.egress;
    for (const AllowEntry& e : overlay.allowlist) base.allowlist.push_back(e);
}

RuleSet default_ruleset() {
    RuleSet rs;
    std::string err;
    if (!load_ruleset_text(default_rules_json(), rs, &err)) {
        // The built-in rules are validated by the unit tests; fall back to an empty set.
        rs = RuleSet{};
    }
    return rs;
}

}
