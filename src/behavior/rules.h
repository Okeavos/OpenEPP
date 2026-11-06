#pragma once

#include "common/json.h"

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace sec::behavior {

enum class RuleEvent { Exec, File, Net, Dns };

// All list fields are "match any" (OR). Different fields combine with AND. Strings are compared
// case-insensitively. An empty field means "no constraint".
struct Condition {
    // process (the acting process)
    std::vector<std::string> name_any;               // exact lowercase basename
    std::vector<std::string> name_not_any;
    std::vector<std::string> path_prefix_any;
    std::vector<std::string> path_contains_any;
    std::vector<std::string> path_not_prefix_any;
    std::vector<std::string> parent_name_any;
    std::vector<std::string> ancestor_name_any;      // any ancestor, excluding the process itself
    std::vector<std::string> args_contains_any;      // substring of the joined command line
    std::vector<std::vector<std::string>> args_all_of_any;  // every group must match (group = OR)
    std::optional<bool> unsigned_process;
    std::optional<bool> platform_binary;

    // file events
    std::vector<std::string> file_path_prefix_any;
    std::vector<std::string> file_path_contains_any;
    std::vector<std::string> file_name_any;
    std::vector<std::string> file_ext_any;           // without the dot

    // network events
    std::vector<int> port_any;
    std::vector<int> port_not_any;
    std::optional<bool> remote_public;

    // correlation
    std::vector<std::string> requires_tag_any;       // tag seen on this process/ancestors within the window
    std::vector<std::string> requires_feature_any;   // engine features (see engine.h)
};

struct Rule {
    std::string id;
    std::string title;      // shown to the user (Korean)
    RuleEvent event = RuleEvent::Exec;
    int score = 0;
    std::string tag;        // tag set on the process when the rule fires
    std::string technique;  // MITRE ATT&CK id, informational
    bool enabled = true;
    int window_s = 0;       // tag window override (0 = ruleset default)
    Condition when;
};

struct EgressPolicy {
    bool enabled = false;
    // Process names (lowercase basename) or path prefixes subject to the allowlist; empty = all processes.
    std::vector<std::string> applies_to;
    // IPv4 / CIDR, or host patterns ("example.com", "*.example.com").
    std::vector<std::string> allow;
    // Extra allowances keyed by process name or path prefix.
    std::map<std::string, std::vector<std::string>> per_process;
};

struct RuleSet {
    std::vector<Rule> rules;
    int warn_threshold = 60;
    int critical_threshold = 100;
    int tag_window_s = 900;
    EgressPolicy egress;
};

// IOC lists: IPs/CIDRs and host patterns.
struct IocSet {
    std::vector<std::string> ips;
    std::vector<std::string> hosts;
};

// Strict loader: unknown keys, bad types and duplicate ids are errors.
bool load_ruleset(const json::Value& doc, RuleSet& out, std::string* error);
bool load_ruleset_text(std::string_view text, RuleSet& out, std::string* error);
bool load_ioc_text(std::string_view text, IocSet& out, std::string* error);

// Built-in macOS-oriented rules.
std::string default_rules_json();
RuleSet default_ruleset();

// Layer `overlay` (a user rule file) over `base` (the built-ins): rules with the same id replace the
// built-in one, new ids append. Thresholds, tag window and the egress policy come from `overlay`.
void merge_ruleset(RuleSet& base, const RuleSet& overlay);

}
