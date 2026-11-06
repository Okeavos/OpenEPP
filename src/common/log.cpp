#include "common/log.h"

#include "common/util.h"

#include <cstdio>
#include <fstream>
#include <mutex>

namespace sec::log {

namespace {

std::mutex g_mutex;
Level g_level = Level::Info;
bool g_console = true;
std::ofstream g_file;

const char* level_name(Level l) {
    switch (l) {
        case Level::Debug: return "DEBUG";
        case Level::Info: return "INFO";
        case Level::Warn: return "WARN";
        case Level::Error: return "ERROR";
    }
    return "?";
}

}

void set_level(Level level) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_level = level;
}

void set_console(bool enabled) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_console = enabled;
}

void set_file(const std::filesystem::path& path) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_file.is_open()) g_file.close();
    if (path.empty()) return;
    std::error_code ec;
    if (path.has_parent_path()) std::filesystem::create_directories(path.parent_path(), ec);
    g_file.open(path, std::ios::app);
}

void write(Level level, std::string_view message) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (static_cast<int>(level) < static_cast<int>(g_level)) return;
    const std::string line = util::now_iso8601() + " [" + level_name(level) + "] " + std::string(message);
    if (g_console) {
        std::FILE* out = (level == Level::Error || level == Level::Warn) ? stderr : stdout;
        std::fprintf(out, "%s\n", line.c_str());
        std::fflush(out);
    }
    if (g_file.is_open()) {
        g_file << line << '\n';
        g_file.flush();
    }
}

Level parse_level(std::string_view name, Level fallback) {
    const std::string n = util::to_lower(std::string(name));
    if (n == "debug") return Level::Debug;
    if (n == "info") return Level::Info;
    if (n == "warn" || n == "warning") return Level::Warn;
    if (n == "error") return Level::Error;
    return fallback;
}

}
