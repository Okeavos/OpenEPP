#pragma once

#include <filesystem>
#include <string_view>

namespace sec::log {

enum class Level { Debug = 0, Info = 1, Warn = 2, Error = 3 };

void set_level(Level level);
void set_console(bool enabled);
// Appends to the given file (parent directories are created). Empty path disables file logging.
void set_file(const std::filesystem::path& path);

void write(Level level, std::string_view message);

inline void debug(std::string_view m) { write(Level::Debug, m); }
inline void info(std::string_view m) { write(Level::Info, m); }
inline void warn(std::string_view m) { write(Level::Warn, m); }
inline void error(std::string_view m) { write(Level::Error, m); }

Level parse_level(std::string_view name, Level fallback);

}
