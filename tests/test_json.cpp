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

TEST(json_integer_edges_without_temporaries) {
    const auto v = json::parse(R"([0,-0,9223372036854775807,-9223372036854775808,9223372036854775808,-12,1e3,1.5,-2.5e-1])");
    CHECK(v.has_value());
    if (!v) return;
    const auto& a = v->items();
    CHECK(a.size() == 9);
    CHECK(a[0].as_int() == 0);
    CHECK(a[1].as_int() == 0);
    CHECK(a[2].as_int() == INT64_MAX);
    CHECK(a[3].as_int() == INT64_MIN);
    CHECK(a[4].as_double() > 9.2e18);  // too large for int64: falls back to double
    CHECK(a[5].as_int() == -12);
    CHECK(a[6].as_double() == 1000.0);
    CHECK(a[7].as_double() == 1.5);
    CHECK(a[8].as_double() == -0.25);
    CHECK(!json::parse("-").has_value());
    CHECK(!json::parse("1.2.3x").has_value());
    CHECK(!json::parse("[1,]").has_value());
}

TEST(json_skip_keys_and_duplicates) {
    const json::ParseOptions opts{{"stat", "junk"}};
    const char* text =
        R"({"a":1,"stat":{"x":[1,2,{"y":"}]\"{"}],"z":"\\"},"b":"keep","junk":"s\"tr","c":[{"stat":5,"d":2}],"a":3})";
    const auto v = json::parse(text, nullptr, opts);
    CHECK(v.has_value());
    if (!v) return;
    CHECK(v->find("stat") == nullptr);
    CHECK(v->find("junk") == nullptr);
    CHECK((*v)["b"].as_string() == "keep");
    CHECK((*v)["a"].as_int() == 3);  // duplicate key: last wins
    CHECK((*v)["c"][0].find("stat") == nullptr);
    CHECK((*v)["c"][0]["d"].as_int() == 2);

    const auto plain = json::parse(text);
    CHECK(plain.has_value() && (*plain)["stat"].is_object());

    std::string err;
    CHECK(!json::parse(R"({"stat":{"x":"unterminated})", &err, opts).has_value());
    CHECK(!err.empty());
    CHECK(!json::parse(R"({"stat":[[[[)", nullptr, opts).has_value());
    CHECK(!json::parse(R"({"stat":1 "b":2})", nullptr, opts).has_value());
    std::string deep = R"({"stat":)";
    for (int i = 0; i < 100; ++i) deep += "[";
    for (int i = 0; i < 100; ++i) deep += "]";
    deep += "}";
    CHECK(!json::parse(deep, nullptr, opts).has_value());
}
