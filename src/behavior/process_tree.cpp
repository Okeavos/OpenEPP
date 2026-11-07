#include "behavior/process_tree.h"

#include "common/util.h"

#include <algorithm>
#include <unordered_set>

namespace sec::behavior {

std::string name_of(const std::string& path) {
    const std::size_t slash = path.find_last_of("/\\");
    return util::to_lower(slash == std::string::npos ? path : path.substr(slash + 1));
}

namespace {

void assign_image(ProcNode& n, const ProcessRef& ref, bool with_args) {
    if (!ref.path.empty()) {
        n.path = ref.path;
        n.name = name_of(ref.path);
    }
    if (with_args) {
        n.args = ref.args;
        n.env = ref.env;
    }
    if (ref.sig_known) {
        n.signing_id = ref.signing_id;
        n.team_id = ref.team_id;
        n.platform_binary = ref.platform_binary;
        n.sig_known = true;
    }
}

}

ProcNode& ProcessTree::create(const ProcessRef& ref, std::int64_t time_ms, bool with_args) {
    ProcNode n;
    n.pid = ref.pid;
    n.ppid = ref.ppid;
    n.start_ms = time_ms;
    assign_image(n, ref, with_args);

    if (ref.ppid != 0 && ref.ppid != ref.pid) {
        const auto pit = nodes_.find(ref.ppid);
        if (pit != nodes_.end()) {
            n.score = pit->second.score;
            n.alert_level = pit->second.alert_level;
            n.tags = pit->second.tags;
        }
    }
    auto result = nodes_.insert_or_assign(ref.pid, std::move(n));
    return result.first->second;
}

ProcNode& ProcessTree::on_exec(const ProcessRef& ref, std::int64_t time_ms) {
    const auto it = nodes_.find(ref.pid);
    if (it != nodes_.end() && !it->second.exited &&
        (ref.ppid == 0 || it->second.ppid == 0 || it->second.ppid == ref.ppid)) {
        ProcNode& n = it->second;
        assign_image(n, ref, true);
        n.hit_ids.clear();
        if (n.ppid == 0) n.ppid = ref.ppid;
        return n;
    }
    return create(ref, time_ms, true);
}

ProcNode& ProcessTree::seed(const ProcessRef& ref, std::int64_t time_ms) {
    const auto it = nodes_.find(ref.pid);
    if (it != nodes_.end() && !it->second.exited) {
        ProcNode& n = it->second;
        assign_image(n, ref, true);
        if (n.ppid == 0) n.ppid = ref.ppid;
        return n;
    }
    return create(ref, time_ms, true);
}

ProcNode& ProcessTree::on_fork(const ProcessRef& child, std::int64_t time_ms) {
    return create(child, time_ms, false);
}

ProcNode& ProcessTree::upsert_actor(const ProcessRef& ref, std::int64_t time_ms) {
    const auto it = nodes_.find(ref.pid);
    if (it == nodes_.end() || it->second.exited) return create(ref, time_ms, false);
    ProcNode& n = it->second;
    if (n.path.empty() || (!n.sig_known && ref.sig_known)) assign_image(n, ref, false);
    if (n.ppid == 0 && ref.ppid != 0) n.ppid = ref.ppid;
    return n;
}

void ProcessTree::on_exit(int pid, std::int64_t time_ms) {
    const auto it = nodes_.find(pid);
    if (it == nodes_.end()) return;
    it->second.exited = true;
    it->second.exit_ms = time_ms;
}

ProcNode* ProcessTree::find(int pid) {
    const auto it = nodes_.find(pid);
    return it == nodes_.end() ? nullptr : &it->second;
}

const ProcNode* ProcessTree::find(int pid) const {
    const auto it = nodes_.find(pid);
    return it == nodes_.end() ? nullptr : &it->second;
}

std::vector<const ProcNode*> ProcessTree::chain(int pid, std::size_t max_depth) const {
    std::vector<const ProcNode*> out;
    std::unordered_set<int> seen;
    const ProcNode* cur = find(pid);
    while (cur != nullptr && out.size() < max_depth && seen.insert(cur->pid).second) {
        out.push_back(cur);
        if (cur->ppid <= 0) break;
        cur = find(cur->ppid);
    }
    return out;
}

void ProcessTree::gc(std::int64_t now_ms) {
    constexpr std::int64_t kKeepExitedMs = 120000;
    for (auto it = nodes_.begin(); it != nodes_.end();) {
        if (it->second.exited && now_ms - it->second.exit_ms > kKeepExitedMs) it = nodes_.erase(it);
        else ++it;
    }
    if (nodes_.size() <= max_nodes_) return;

    std::vector<std::pair<std::int64_t, int>> order;
    order.reserve(nodes_.size());
    for (const auto& kv : nodes_) {
        order.emplace_back(kv.second.exited ? kv.second.exit_ms - (1LL << 40) : kv.second.start_ms, kv.first);
    }
    std::sort(order.begin(), order.end());
    const std::size_t excess = nodes_.size() - max_nodes_;
    for (std::size_t i = 0; i < excess && i < order.size(); ++i) nodes_.erase(order[i].second);
}

}
