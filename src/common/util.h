#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sec::util {

std::string to_lower(std::string s);
std::string trim(std::string_view s);
std::vector<std::string> split(std::string_view s, char delim);

// Reads a whole file. Fails (returns false) if the file is larger than max_bytes.
bool read_file(const std::filesystem::path& path, std::vector<std::uint8_t>& out, std::uint64_t max_bytes);

// Streaming SHA-256 of a file, lowercase hex.
std::optional<std::string> sha256_file(const std::filesystem::path& path);

// UTC timestamp, e.g. 2026-11-05T12:34:56Z
std::string now_iso8601();

std::string path_to_utf8(const std::filesystem::path& p);
std::filesystem::path path_from_utf8(const std::string& s);

bool is_hex(std::string_view s);

}
