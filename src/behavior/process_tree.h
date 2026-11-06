#pragma once

#include "behavior/event.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace sec::behavior {

// Lowercase basename of a path ("/Applications/Google Chrome.app/.../Google Chrome" -> "google chrome").
std::string name_of(const std::string& path);

struct ProcNode {
    int pid = 0;
    int ppid = 0;
    std::string path;
    std::string name;  // lowercase basename
    std::vector<std::string> args;
    std::string signing_id;
    std::string team_id;
    bool platform_binary = false;
    bool sig_known = false;
    std::int64_t start_ms = 0;
    bool exited = false;
    std::int64_t exit_ms = 0;

    int score = 0;        // accumulated (inherited from the parent at creation)
    int alert_level = 0;  // 0 none, 1 warning, 2 critical (inherited)
    std::map<std::string, std::int64_t> tags;  // tag -> last time_ms (inherited)
    std::set<std::string> hit_ids;             // rules that already fired for this image
    std::vector<std::string> hits;             // ordered rule ids (this process only)

    // Known to be neither an Apple platform binary nor signed by a developer team.
    bool is_unsigned() const { return sig_known && !platform_binary && team_id.empty(); }
};

class ProcessTree {
public:
    explicit ProcessTree(std::size_t max_nodes = 20000) : max_nodes_(max_nodes) {}

    // New image for a pid (new process or re-exec). Children inherit score/tags/alert level.
    ProcNode& on_exec(const ProcessRef& ref, std::int64_t time_ms);
    // Child created by fork (same image as its parent until it execs).
    ProcNode& on_fork(const ProcessRef& child, std::int64_t time_ms);
    // Process seen as the actor of a non-exec event; fills in missing details.
    ProcNode& upsert_actor(const ProcessRef& ref, std::int64_t time_ms);
    void on_exit(int pid, std::int64_t time_ms);

    ProcNode* find(int pid);
    const ProcNode* find(int pid) const;

    // self first, then ancestors (at most max_depth entries).
    std::vector<const ProcNode*> chain(int pid, std::size_t max_depth = 12) const;

    void gc(std::int64_t now_ms);
    std::size_t size() const { return nodes_.size(); }

private:
    ProcNode& create(const ProcessRef& ref, std::int64_t time_ms, bool with_args);

    std::size_t max_nodes_;
    std::unordered_map<int, ProcNode> nodes_;
};

}
