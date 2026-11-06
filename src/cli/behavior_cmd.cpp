#include "cli/behavior_cmd.h"

#include "behavior/engine.h"
#include "behavior/es_parser.h"
#include "behavior/rules.h"
#include "common/util.h"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

using namespace sec;

namespace {

bool read_text_file(const std::string& path, std::string& out) {
    std::ifstream in(util::path_from_utf8(path), std::ios::binary);
    if (!in) return false;
    std::ostringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    return true;
}

}

int run_behavior_rules() {
    std::fputs(behavior::default_rules_json().c_str(), stdout);
    return 0;
}

int run_behavior_replay(int argc, char** argv, int from) {
    std::string input;
    std::string rules_path;
    std::string ioc_path;
    bool as_json = false;
    for (int i = from; i < argc; ++i) {
        const std::string s = argv[i];
        if (s == "--rules" && i + 1 < argc) rules_path = argv[++i];
        else if (s == "--ioc" && i + 1 < argc) ioc_path = argv[++i];
        else if (s == "--json") as_json = true;
        else if (input.empty()) input = s;
    }
    if (input.empty()) {
        std::fputs("usage: sec-cli behavior-replay <events.jsonl|-> [--rules <file>] [--ioc <file>] [--json]\n", stderr);
        return 2;
    }

    behavior::RuleSet rules = behavior::default_ruleset();
    if (rules.rules.empty()) {
        std::fputs("internal error: built-in rules failed to load\n", stderr);
        return 1;
    }
    if (!rules_path.empty()) {
        std::string text;
        std::string err;
        behavior::RuleSet overlay;
        if (!read_text_file(rules_path, text)) {
            std::fprintf(stderr, "cannot read rules file: %s\n", rules_path.c_str());
            return 1;
        }
        if (!behavior::load_ruleset_text(text, overlay, &err)) {
            std::fprintf(stderr, "invalid rules file: %s\n", err.c_str());
            return 1;
        }
        behavior::merge_ruleset(rules, overlay);
    }

    behavior::Engine engine(std::move(rules));
    if (!ioc_path.empty()) {
        std::string text;
        std::string err;
        behavior::IocSet ioc;
        if (!read_text_file(ioc_path, text)) {
            std::fprintf(stderr, "cannot read IOC file: %s\n", ioc_path.c_str());
            return 1;
        }
        if (!behavior::load_ioc_text(text, ioc, &err)) {
            std::fprintf(stderr, "invalid IOC file: %s\n", err.c_str());
            return 1;
        }
        engine.set_ioc(std::move(ioc));
    }

    std::ifstream file;
    std::istream* in = &std::cin;
    if (input != "-") {
        file.open(util::path_from_utf8(input), std::ios::binary);
        if (!file) {
            std::fprintf(stderr, "cannot open input: %s\n", input.c_str());
            return 1;
        }
        in = &file;
    }

    std::size_t lines = 0, events = 0, skipped = 0, errors = 0, alerts = 0;
    std::int64_t last_ms = 0;
    std::string line;
    while (std::getline(*in, line)) {
        ++lines;
        behavior::ParseResult r = behavior::parse_event_line(line);
        if (r.status == behavior::ParseResult::Status::Error) {
            ++errors;
            if (errors <= 10) std::fprintf(stderr, "line %zu: %s\n", lines, r.error.c_str());
            continue;
        }
        if (!r.ok()) {
            ++skipped;
            continue;
        }
        ++events;
        if (r.event.time_ms == 0) r.event.time_ms = last_ms + 1;
        if (r.event.time_ms > last_ms) last_ms = r.event.time_ms;
        for (const behavior::Alert& a : engine.process(r.event)) {
            ++alerts;
            const std::string out = as_json ? behavior::alert_to_json(a) + "\n" : behavior::alert_to_text(a);
            std::fputs(out.c_str(), stdout);
        }
    }
    std::fprintf(stderr, "events=%zu skipped=%zu parse_errors=%zu alerts=%zu\n", events, skipped, errors, alerts);
    return errors == 0 ? 0 : 3;
}
