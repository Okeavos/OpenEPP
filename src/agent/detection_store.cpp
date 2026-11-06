#include "agent/detection_store.h"

#include "common/util.h"

#include <fstream>

namespace fs = std::filesystem;

namespace sec {

namespace {

std::string clean_field(std::string s) {
    for (char& c : s) {
        if (c == '\t' || c == '\n' || c == '\r') c = ' ';
    }
    return s;
}

}

DetectionStore::DetectionStore(fs::path file, std::size_t max_in_memory)
    : file_(std::move(file)), max_(max_in_memory == 0 ? 1 : max_in_memory) {}

void DetectionStore::load() {
    std::lock_guard<std::mutex> lock(mutex_);
    records_.clear();
    total_ = 0;
    std::ifstream f(file_);
    std::string line;
    while (std::getline(f, line)) {
        const std::vector<std::string> p = util::split(line, '\t');
        if (p.size() < 7) continue;
        DetectionRecord r;
        r.time = p[0];
        r.verdict = p[1];
        try {
            r.score = std::stoi(p[2]);
        } catch (...) {
            r.score = 0;
        }
        r.threat = p[3];
        r.action = p[4];
        r.sha256 = p[5];
        r.path = p[6];
        records_.push_back(std::move(r));
        ++total_;
        if (records_.size() > max_) records_.erase(records_.begin());
    }
    seen_ = total_;
}

void DetectionStore::add(DetectionRecord record) {
    record.path = clean_field(record.path);
    record.threat = clean_field(record.threat);
    record.action = clean_field(record.action);
    record.verdict = clean_field(record.verdict);
    record.time = clean_field(record.time);
    record.sha256 = clean_field(record.sha256);

    std::lock_guard<std::mutex> lock(mutex_);
    if (record.action == "none") {
        for (const DetectionRecord& r : records_) {
            if (r.action == "none" && r.path == record.path && r.sha256 == record.sha256) return;
        }
    }
    std::error_code ec;
    if (file_.has_parent_path()) fs::create_directories(file_.parent_path(), ec);
    {
        std::ofstream f(file_, std::ios::app);
        if (f) {
            f << record.time << '\t' << record.verdict << '\t' << record.score << '\t' << record.threat << '\t'
              << record.action << '\t' << record.sha256 << '\t' << record.path << '\n';
        }
    }
    records_.push_back(std::move(record));
    ++total_;
    if (records_.size() > max_) records_.erase(records_.begin());
}

std::vector<DetectionRecord> DetectionStore::recent() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::vector<DetectionRecord>(records_.rbegin(), records_.rend());
}

std::size_t DetectionStore::total() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return total_;
}

std::size_t DetectionStore::unseen() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return total_ - seen_;
}

void DetectionStore::mark_seen() {
    std::lock_guard<std::mutex> lock(mutex_);
    seen_ = total_;
}

}
