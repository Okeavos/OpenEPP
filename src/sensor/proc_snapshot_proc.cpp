// Non-macOS fallback: read /proc. No signing information is available, so sig_known stays false.

#include "sensor/proc_snapshot.h"

#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <system_error>

namespace fs = std::filesystem;

namespace sec::sensor {

namespace {

bool parse_pid(const std::string& name, int& pid) {
    if (name.empty() || name.size() > 9) return false;
    int v = 0;
    for (const char c : name) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
        v = v * 10 + (c - '0');
    }
    pid = v;
    return true;
}

int read_ppid(const fs::path& stat_file) {
    std::ifstream in(stat_file);
    std::string line;
    if (!std::getline(in, line)) return 0;
    // "pid (comm) S ppid ..." ; comm may contain spaces and parentheses, so search from the last ')'.
    const std::size_t close = line.rfind(')');
    if (close == std::string::npos) return 0;
    std::istringstream rest(line.substr(close + 1));
    std::string state;
    int ppid = 0;
    rest >> state >> ppid;
    return ppid;
}

std::vector<std::string> read_cmdline(const fs::path& file) {
    std::vector<std::string> args;
    std::ifstream in(file, std::ios::binary);
    std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::size_t start = 0;
    while (start < data.size()) {
        const std::size_t nul = data.find('\0', start);
        const std::size_t end = nul == std::string::npos ? data.size() : nul;
        args.push_back(data.substr(start, end - start));
        start = end + 1;
    }
    return args;
}

}

std::vector<behavior::ProcessRef> snapshot_processes() {
    std::vector<behavior::ProcessRef> out;
    std::error_code ec;
    for (const fs::directory_entry& e : fs::directory_iterator("/proc", ec)) {
        int pid = 0;
        if (!parse_pid(e.path().filename().string(), pid) || pid <= 0) continue;

        behavior::ProcessRef r;
        r.pid = pid;
        r.ppid = read_ppid(e.path() / "stat");
        std::error_code lec;
        const fs::path exe = fs::read_symlink(e.path() / "exe", lec);
        if (lec) continue;  // kernel threads and processes we may not inspect
        r.path = exe.string();
        r.args = read_cmdline(e.path() / "cmdline");
        out.push_back(std::move(r));
    }
    return out;
}

}
