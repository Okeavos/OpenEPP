#pragma once

// AI coding agent / MCP configuration files: recognising them by path and looking inside them for
// entries that would run attacker-controlled commands the next time the agent starts.
//
// Why: a hijacked agent (prompt injection through an issue, a log, a repository file) or a
// malicious package install script can add an MCP server, a hook or an API endpoint to these files.
// The change runs with the developer's own rights on every later session, and nothing on disk
// looks like malware, so the file contents are the place to look.

#include <string>
#include <string_view>
#include <vector>

namespace sec::behavior {

// `lower_path` must be lowercase. Matches e.g. .mcp.json, .cursor/mcp.json, .vscode/mcp.json,
// ~/.claude.json, ~/.claude/settings*.json, claude_desktop_config.json, ~/.gemini/settings.json,
// ~/.codex/config.toml and the instruction files AGENTS.md / CLAUDE.md / GEMINI.md / .cursorrules.
bool is_agent_config_path(std::string_view lower_path);

// Human readable findings (Korean) for one file's contents; empty when nothing stands out.
// JSON files get structural checks (MCP servers, hooks, API endpoints, permission settings),
// TOML files line checks, instruction files checks for hidden text.
std::vector<std::string> inspect_agent_config(std::string_view path, std::string_view text);

// Reads the file (at most 1 MiB) and inspects it. A missing or unreadable file yields no findings.
std::vector<std::string> inspect_agent_config_file(const std::string& path);

// Reason a command line looks dangerous for an MCP server or hook ("" if it doesn't). Lowercase input.
std::string suspicious_command(std::string_view lower_cmdline);

}
