#include "test_framework.h"

#include "common/json.h"

using namespace sec;

TEST(json_parses_scalars_and_containers) {
    std::string err;
    const auto v = json::parse(R"({"a":1,"b":-2.5e1,"c":"x","d":[true,false,null],"e":{"f":[]}})", &err);
    CHECK(v.has_value());
    CHECK(v->is_object());
    CHECK((*v)["a"].as_int() == 1);
    CHECK((*v)["b"].as_double() == -25.0);
    CHECK((*v)["c"].as_string() == "x");
    CHECK((*v)["d"].size() == 3);
    CHECK((*v)["d"][0].as_bool());
    CHECK(!(*v)["d"][1].as_bool(true));
    CHECK((*v)["d"][2].is_null());
    CHECK((*v)["e"]["f"].is_array());
    CHECK((*v)["missing"].is_null());
    CHECK((*v)["missing"]["deeper"].is_null());
    CHECK(v->find("missing") == nullptr);
    CHECK((*v)["d"][99].is_null());
}

TEST(json_string_escapes_and_unicode) {
    const auto v = json::parse(R"(["a\"b\\c\/d\n\t","\u00e9","\u0041","\ud83d\ude00"])");
    CHECK(v.has_value());
    CHECK((*v)[0].as_string() == "a\"b\\c/d\n\t");
    CHECK((*v)[1].as_string() == "\xC3\xA9");
    CHECK((*v)[2].as_string() == "A");
    CHECK((*v)[3].as_string() == "\xF0\x9F\x98\x80");
}

TEST(json_rejects_malformed_input) {
    const char* bad[] = {"",        "{",        "[1,]",       "{\"a\":}",  "{\"a\" 1}", "[1 2]",
                         "\"abc",   "tru",      "01x",        "{1:2}",     "[1] x",     "\"\\q\"",
                         "\"\\ud800\"", "\"\\u12\"", "-", "{\"a\":1,}"};
    for (const char* s : bad) {
        std::string err;
        CHECK(!json::parse(s, &err).has_value());
        CHECK(!err.empty());
    }
}

TEST(json_depth_limit) {
    std::string deep(200, '[');
    deep += std::string(200, ']');
    CHECK(!json::parse(deep).has_value());
    std::string ok(30, '[');
    ok += std::string(30, ']');
    CHECK(json::parse(ok).has_value());
}

TEST(json_duplicate_keys_last_wins_and_order_kept) {
    const auto v = json::parse(R"({"b":1,"a":2,"b":3})");
    CHECK(v.has_value());
    CHECK(v->keys().size() == 2);
    CHECK(v->keys()[0] == "b");
    CHECK((*v)["b"].as_int() == 3);
}

TEST(json_large_integers) {
    const auto v = json::parse("[9007199254740993, 1.5, 123456789012]");
    CHECK(v.has_value());
    CHECK((*v)[0].as_int() == 9007199254740993LL);
    CHECK((*v)[2].as_int() == 123456789012LL);
}
