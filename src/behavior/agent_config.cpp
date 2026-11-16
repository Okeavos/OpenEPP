#include "behavior/agent_config.h"

#include "common/json.h"
#include "common/util.h"

#include <fstream>
#include <iterator>

namespace sec::behavior {

namespace {

bool ends_with(std::string_view s, std::string_view suffix) {
    return s.size() >= suffix.size() && s.substr(s.size() - suffix.size()) == suffix;
}

bool has(std::string_view s, std::string_view sub) { return s.find(sub) != std::string_view::npos; }

std::string_view base_name(std::string_view p) {
    const std::size_t slash = p.find_last_of('/');
    return slash == std::string_view::npos ? p : p.substr(slash + 1);
}

std::string lower(std::string_view s) { return util::to_lower(std::string(s)); }

void add(std::vector<std::string>& out, std::string f) {
    constexpr std::size_t kMax = 12;
    if (out.size() >= kMax) return;
    for (const std::string& x : out) {
        if (x == f) return;
    }
    out.push_back(std::move(f));
}

std::string clip(std::string s) {
    constexpr std::size_t kMax = 80;
    if (s.size() > kMax) s = s.substr(0, kMax) + "...";
    return s;
}

// Host part of an http(s) URL, lowercased.
std::string url_host(std::string_view url) {
    const std::size_t scheme = url.find("://");
    if (scheme == std::string_view::npos) return std::string();
    std::string_view rest = url.substr(scheme + 3);
    const std::size_t end = rest.find_first_of("/:?#");
    if (end != std::string_view::npos) rest = rest.substr(0, end);
    const std::size_t at = rest.find('@');
    if (at != std::string_view::npos) rest = rest.substr(at + 1);
    return lower(rest);
}

bool is_local_host(const std::string& h) { return h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "[::1]"; }

bool host_is_or_under(const std::string& host, std::string_view domain) {
    return host == domain || ends_with(host, std::string(".") + std::string(domain));
}

std::string joined_command(const json::Value& server) {
    std::string cmd = server["command"].as_string();
    if (const json::Value* args = server.find("args")) {
        for (const json::Value& a : args->items()) {
            cmd.push_back(' ');
            cmd += a.as_string();
        }
    }
    return lower(cmd);
}

void check_env_block(const json::Value& env, const std::string& where, std::vector<std::string>& out) {
    if (!env.is_object()) return;
    for (std::size_t i = 0; i < env.keys().size(); ++i) {
        const std::string key = lower(env.keys()[i]);
        const std::string val = lower(env.items()[i].as_string());
        if (key == "dyld_insert_libraries") add(out, where + ": DYLD_INSERT_LIBRARIES로 라이브러리 주입");
        if (key == "node_options" && (has(val, "--require") || has(val, "-r ") || has(val, "--import"))) {
            add(out, where + ": NODE_OPTIONS로 코드를 미리 불러옴");
        }
        if (key == "anthropic_base_url" || key == "anthropic_api_url" || key == "openai_base_url" ||
            key == "openai_api_base" || key == "gemini_api_base_url" || key == "google_gemini_base_url") {
            const std::string h = url_host(val);
            const bool known = h.empty() || is_local_host(h) || host_is_or_under(h, "anthropic.com") ||
                               host_is_or_under(h, "openai.com") || host_is_or_under(h, "googleapis.com") ||
                               host_is_or_under(h, "azure.com") || host_is_or_under(h, "amazonaws.com");
            if (!known) add(out, where + ": AI API 요청 주소를 외부 호스트로 변경 (" + clip(h) + ")");
        }
        if ((key == "https_proxy" || key == "http_proxy" || key == "all_proxy") && !val.empty()) {
            const std::string h = url_host(val);
            if (!is_local_host(h)) add(out, where + ": 외부 프록시 지정 (" + clip(h) + ")");
        }
    }
}

void check_servers(const json::Value& servers, std::vector<std::string>& out) {
    if (!servers.is_object()) return;
    for (std::size_t i = 0; i < servers.keys().size(); ++i) {
        const json::Value& s = servers.items()[i];
        if (!s.is_object()) continue;
        const std::string where = "MCP 서버 '" + clip(servers.keys()[i]) + "'";
        const std::string cmd = joined_command(s);
        if (!cmd.empty()) {
            const std::string why = suspicious_command(cmd);
            if (!why.empty()) add(out, where + ": " + why);
        }
        const std::string url = lower(s["url"].as_string());
        if (url.rfind("http://", 0) == 0 && !is_local_host(url_host(url))) {
            add(out, where + ": 암호화되지 않은 원격 서버 (" + clip(url_host(url)) + ")");
        }
        if (const json::Value* env = s.find("env")) check_env_block(*env, where, out);
    }
}

// Every "command" string under the hooks object (Claude Code: hooks.<Event>[].hooks[].command).
void check_hooks(const json::Value& v, int depth, std::vector<std::string>& out) {
    if (depth > 8) return;
    if (v.is_object()) {
        for (std::size_t i = 0; i < v.keys().size(); ++i) {
            const json::Value& c = v.items()[i];
            if (v.keys()[i] == "command" && c.is_string()) {
                const std::string why = suspicious_command(lower(c.as_string()));
                if (!why.empty()) add(out, "훅 명령: " + why + " (" + clip(c.as_string()) + ")");
            } else {
                check_hooks(c, depth + 1, out);
            }
        }
    } else if (v.is_array()) {
        for (const json::Value& c : v.items()) check_hooks(c, depth + 1, out);
    }
}

void check_settings(const json::Value& doc, std::vector<std::string>& out) {
    if (const json::Value* hooks = doc.find("hooks")) check_hooks(*hooks, 0, out);
    if (const json::Value* helper = doc.find("apiKeyHelper")) {
        const std::string why = suspicious_command(lower(helper->as_string()));
        if (!why.empty()) add(out, "apiKeyHelper: " + why);
    }
    if (const json::Value* env = doc.find("env")) check_env_block(*env, "env", out);
    if (const json::Value* perms = doc.find("permissions")) {
        if (lower((*perms)["defaultMode"].as_string()) == "bypasspermissions") {
            add(out, "권한 확인 비활성화 (defaultMode: bypassPermissions)");
        }
        if (const json::Value* allow = perms->find("allow")) {
            for (const json::Value& a : allow->items()) {
                const std::string s = lower(a.as_string());
                if (s == "bash" || s == "bash(*)" || s == "bash(*:*)") add(out, "모든 셸 명령 자동 허용 (" + a.as_string() + ")");
            }
        }
    }
    if (doc["enableAllProjectMcpServers"].as_bool()) add(out, "프로젝트 MCP 서버 자동 승인 (enableAllProjectMcpServers)");
}

// mcpServers can sit at the top level or per project (~/.claude.json: projects.<dir>.mcpServers).
void find_mcp_servers(const json::Value& v, int depth, std::vector<std::string>& out) {
    if (depth > 4 || !v.is_object()) return;
    for (std::size_t i = 0; i < v.keys().size(); ++i) {
        if (v.keys()[i] == "mcpServers" || v.keys()[i] == "mcp_servers") check_servers(v.items()[i], out);
        else find_mcp_servers(v.items()[i], depth + 1, out);
    }
}

// Characters that do not render: zero-width, bidirectional overrides, BOM inside text, and the Unicode
// "tag" block (U+E0000..U+E007F) that can carry invisible ASCII.
bool has_invisible_chars(std::string_view t) {
    for (std::size_t i = 0; i + 2 < t.size(); ++i) {
        const unsigned char a = static_cast<unsigned char>(t[i]);
        const unsigned char b = static_cast<unsigned char>(t[i + 1]);
        const unsigned char c = static_cast<unsigned char>(t[i + 2]);
        if (a == 0xE2 && b == 0x80 && ((c >= 0x8B && c <= 0x8F) || (c >= 0xAA && c <= 0xAE))) return true;
        if (a == 0xE2 && b == 0x81 && (c == 0xA0 || (c >= 0xA6 && c <= 0xA9))) return true;
        if (a == 0xEF && b == 0xBB && c == 0xBF && i != 0) return true;
        if (a == 0xF3 && b == 0xA0 && (c == 0x80 || c == 0x81)) return true;
    }
    return false;
}

void check_instructions(std::string_view text, std::vector<std::string>& out) {
    if (has_invisible_chars(text)) add(out, "보이지 않는 문자 포함 (숨은 지시문 의심)");
    const std::string t = lower(text);
    static const char* const kOverride[] = {"ignore previous instructions", "ignore all previous", "ignore the above",
                                            "disregard previous instructions", "disregard all prior",
                                            "이전 지시를 무시", "이전 지시사항을 무시"};
    for (const char* k : kOverride) {
        if (has(t, k)) {
            add(out, "이전 지시를 무시하라는 문구");
            break;
        }
    }
    std::size_t pos = 0;
    while ((pos = t.find("<!--", pos)) != std::string::npos) {
        const std::size_t end = t.find("-->", pos + 4);
        const std::string_view body =
            std::string_view(t).substr(pos + 4, (end == std::string::npos ? t.size() : end) - pos - 4);
        if (!suspicious_command(body).empty() || has(body, "curl ") || has(body, "wget ")) {
            add(out, "HTML 주석 안에 숨은 명령");
            break;
        }
        if (end == std::string::npos) break;
        pos = end + 3;
    }
}

void check_toml(std::string_view text, std::vector<std::string>& out) {
    const std::string t = lower(text);
    std::size_t start = 0;
    while (start < t.size()) {
        std::size_t end = t.find('\n', start);
        if (end == std::string::npos) end = t.size();
        const std::string_view line = std::string_view(t).substr(start, end - start);
        if (has(line, "command") || has(line, "args")) {
            // command = "/path" / args = ["-c", "..."]: check the quoted values joined like argv.
            std::string cmd;
            std::size_t q = line.find('"');
            while (q != std::string_view::npos) {
                const std::size_t e = line.find('"', q + 1);
                if (e == std::string_view::npos) break;
                if (!cmd.empty()) cmd.push_back(' ');
                cmd.append(line.substr(q + 1, e - q - 1));
                q = line.find('"', e + 1);
            }
            const std::string why = suspicious_command(cmd.empty() ? std::string(line) : cmd);
            if (!why.empty()) add(out, "MCP 서버 설정: " + why);
        }
        if (has(line, "danger-full-access")) add(out, "샌드박스 해제 (danger-full-access)");
        if (has(line, "approval_policy") && has(line, "never")) add(out, "명령 실행 승인 생략 (approval_policy = never)");
        start = end + 1;
    }
}

}

bool is_agent_config_path(std::string_view p) {
    const std::string_view name = base_name(p);
    if (name == ".mcp.json" || name == "claude_desktop_config.json" || name == ".claude.json") return true;
    if (name == "agents.md" || name == "claude.md" || name == "gemini.md" || name == ".cursorrules" ||
        name == ".windsurfrules" || name == "claude.local.md") {
        return true;
    }
    if (name == "mcp.json") return has(p, "/.cursor/") || has(p, "/.vscode/") || has(p, "/.amazonq/") || has(p, "/.kiro/");
    if (name == "settings.json" || name == "settings.local.json") return has(p, "/.claude/") || has(p, "/.gemini/");
    if (name == "config.toml") return has(p, "/.codex/");
    if (has(p, "/.cursor/rules/") && ends_with(name, ".mdc")) return true;
    return false;
}

std::string suspicious_command(std::string_view c) {
    const std::string_view first = c.substr(0, c.find(' '));
    const std::string_view exe = base_name(first);
    const bool shell = exe == "sh" || exe == "bash" || exe == "zsh" || exe == "dash" || exe == "ksh";
    if (has(c, "/dev/tcp/") || has(c, "/dev/udp/")) return "리버스 셸 패턴";
    if ((has(c, "curl ") || has(c, "wget ")) &&
        (has(c, "| sh") || has(c, "|sh") || has(c, "| bash") || has(c, "|bash") || has(c, "| zsh") || has(c, "|zsh"))) {
        return "원격 스크립트를 내려받아 셸로 실행";
    }
    if (has(c, "base64 -d") || has(c, "base64 --decode") || has(c, "frombase64")) {
        return "base64로 숨긴 명령";
    }
    if (has(c, "curl ") || has(c, "wget ")) return "실행할 때마다 외부에서 내려받음 (curl/wget)";
    if (has(c, "osascript")) return "AppleScript 실행";
    if (shell && (has(c, " -c ") || ends_with(c, " -c"))) return "셸 명령을 직접 실행 (sh -c)";
    if (has(c, "python -c ") || has(c, "python3 -c ") || has(c, "node -e ") || has(c, "node --eval") ||
        has(c, "perl -e ") || has(c, "ruby -e ")) {
        return "인라인 스크립트 실행";
    }
    if (first.rfind("/tmp/", 0) == 0 || first.rfind("/private/tmp/", 0) == 0 || first.rfind("/var/tmp/", 0) == 0 ||
        first.rfind("/users/shared/", 0) == 0 || has(first, "/downloads/")) {
        return "임시·다운로드 폴더의 실행 파일";
    }
    return std::string();
}

std::vector<std::string> inspect_agent_config(std::string_view path, std::string_view text) {
    std::vector<std::string> out;
    const std::string lp = lower(path);
    const std::string_view name = base_name(lp);
    if (ends_with(name, ".md") || ends_with(name, ".mdc") || name == ".cursorrules" || name == ".windsurfrules") {
        check_instructions(text, out);
        return out;
    }
    if (ends_with(name, ".toml")) {
        check_toml(text, out);
        return out;
    }
    const auto doc = json::parse(text);
    if (!doc || !doc->is_object()) return out;
    find_mcp_servers(*doc, 0, out);
    if (name == "mcp.json") {
        if (const json::Value* s = doc->find("servers")) check_servers(*s, out);  // VS Code layout
    }
    check_settings(*doc, out);
    return out;
}

std::vector<std::string> inspect_agent_config_file(const std::string& path) {
    constexpr std::size_t kMaxBytes = 1u << 20;
    std::ifstream in(util::path_from_utf8(path), std::ios::binary);
    if (!in) return {};
    std::string text;
    text.resize(kMaxBytes);
    in.read(text.data(), static_cast<std::streamsize>(kMaxBytes));
    text.resize(static_cast<std::size_t>(in.gcount()));
    return inspect_agent_config(path, text);
}

}
