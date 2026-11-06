#pragma once

#include "behavior/event.h"
#include "behavior/process_tree.h"
#include "behavior/rules.h"

#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

namespace sec::behavior {

struct Alert {
    std::int64_t time_ms = 0;
    int level = 0;  // 1 = warning, 2 = critical
    int score = 0;
    int pid = 0;
    std::string process_path;
    std::string title;                    // human readable summary (Korean)
    std::vector<std::string> rule_ids;    // rules that contributed along the process chain, oldest first
    std::vector<std::string> techniques;  // MITRE ATT&CK ids
    std::vector<std::string> chain;       // "launchd(1) > bash(512) > payload(900)"
    std::string detail;                   // the triggering event
};

std::string alert_to_json(const Alert& a);
std::string alert_to_text(const Alert& a);

// Features that rules can require via "requires_feature_any":
//   recent_download_exec  a file written by a non-build tool within the last hour is being executed
//   beaconing             >=6 connections from one process to one destination at regular intervals
//   ioc_match             destination IP / host matches the IOC set
//   dga_like              queried/connected host name looks algorithmically generated
//   tunnel_like           DNS name shaped like DNS tunnelling
//   egress_violation      public destination not covered by the egress allowlist
class Engine {
public:
    explicit Engine(RuleSet rules);

    void set_ioc(IocSet ioc) { ioc_ = std::move(ioc); }
    const RuleSet& rules() const { return rules_; }
    const ProcessTree& tree() const { return tree_; }

    // Feed one normalized event in time order; returns alerts raised by it.
    std::vector<Alert> process(const Event& ev);

    std::uint64_t events_processed() const { return events_; }

private:
    struct Written {
        std::int64_t time_ms = 0;
        std::string writer;
    };

    // Lowercased, per-event derived values shared by all rule evaluations.
    struct EvalCtx {
        std::string path;      // process image path
        std::string cmdline;   // joined argv (falls back to the path)
        std::string file_path;
        std::string file_name;
        std::string file_ext;
        std::string parent_name;
        bool has_parent = false;
        bool remote_public = false;  // net events: destination is a public internet address
        int remote_port = 0;
        std::vector<std::string> ancestors;  // names of ancestors, nearest first
        std::vector<std::string> features;
    };

    std::vector<std::string> compute_features(const Event& ev, const ProcNode& node, const EvalCtx& ctx);
    bool beacon_check(const Event& ev);
    bool ioc_match(const Event& ev) const;
    bool egress_violation(const Event& ev, const ProcNode& node, const EvalCtx& ctx) const;
    bool match_condition(const Rule& rule, const ProcNode& node, const EvalCtx& ctx, std::int64_t now_ms) const;
    void note_file_write(const Event& ev, const ProcNode& node);

    RuleSet rules_;
    IocSet ioc_;
    ProcessTree tree_;
    std::vector<std::size_t> rules_by_event_[4];  // indexes into rules_.rules, by RuleEvent
    std::unordered_map<std::string, std::size_t> rule_index_;
    std::unordered_map<std::string, Written> written_;
    std::map<std::string, std::deque<std::int64_t>> beacons_;
    std::uint64_t events_ = 0;
};

}
