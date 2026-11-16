#include "common/json.h"

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace sec::json {

Value Value::make_bool(bool b) {
    Value v;
    v.type_ = Type::Bool;
    v.bool_ = b;
    return v;
}

Value Value::make_number(double d, bool is_int, std::int64_t i) {
    Value v;
    v.type_ = Type::Number;
    v.double_ = d;
    v.is_int_ = is_int;
    v.int_ = i;
    return v;
}

Value Value::make_string(std::string s) {
    Value v;
    v.type_ = Type::String;
    v.string_ = std::move(s);
    return v;
}

Value Value::make_array() {
    Value v;
    v.type_ = Type::Array;
    return v;
}

Value Value::make_object() {
    Value v;
    v.type_ = Type::Object;
    return v;
}

const Value& Value::null_value() {
    static const Value kNull;
    return kNull;
}

bool Value::as_bool(bool fallback) const { return type_ == Type::Bool ? bool_ : fallback; }

double Value::as_double(double fallback) const {
    if (type_ != Type::Number) return fallback;
    return is_int_ ? static_cast<double>(int_) : double_;
}

std::int64_t Value::as_int(std::int64_t fallback) const {
    if (type_ != Type::Number) return fallback;
    return is_int_ ? int_ : static_cast<std::int64_t>(double_);
}

const std::string& Value::as_string() const {
    static const std::string kEmpty;
    return type_ == Type::String ? string_ : kEmpty;
}

const Value* Value::find(std::string_view key) const {
    if (type_ != Type::Object) return nullptr;
    for (std::size_t i = 0; i < keys_.size(); ++i) {
        if (keys_[i] == key) return &items_[i];
    }
    return nullptr;
}

const Value& Value::operator[](std::string_view key) const {
    const Value* v = find(key);
    return v != nullptr ? *v : null_value();
}

const Value& Value::operator[](std::size_t index) const {
    if (type_ != Type::Array || index >= items_.size()) return null_value();
    return items_[index];
}

void Value::push_back(Value v) { items_.push_back(std::move(v)); }

void Value::set(std::string key, Value v) {
    for (std::size_t i = 0; i < keys_.size(); ++i) {
        if (keys_[i] == key) {
            items_[i] = std::move(v);
            return;
        }
    }
    keys_.push_back(std::move(key));
    items_.push_back(std::move(v));
}

namespace detail {

constexpr int kMaxDepth = 64;

// Parses straight into the destination Value (no std::optional or temporary per element), which
// matters for eslogger lines: several KB of nested objects per event.
class Parser {
public:
    explicit Parser(std::string_view text, const ParseOptions* opts = nullptr) : s_(text), opts_(opts) {}

    std::optional<Value> run(std::string* error) {
        Value out;
        skip_ws();
        bool ok = parse_value(0, out);
        if (ok) {
            skip_ws();
            if (pos_ != s_.size()) {
                fail("unexpected trailing characters");
                ok = false;
            }
        }
        if (!ok) {
            if (error != nullptr) *error = error_ + " at offset " + std::to_string(pos_);
            return std::nullopt;
        }
        return out;
    }

private:
    void fail(const char* msg) {
        if (error_.empty()) error_ = msg;
    }

    void skip_ws() {
        while (pos_ < s_.size()) {
            const char c = s_[pos_];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') ++pos_;
            else break;
        }
    }

    bool consume_literal(std::string_view lit) {
        if (s_.substr(pos_, lit.size()) == lit) {
            pos_ += lit.size();
            return true;
        }
        return false;
    }

    bool parse_value(int depth, Value& out) {
        if (depth > kMaxDepth) {
            fail("nesting too deep");
            return false;
        }
        if (pos_ >= s_.size()) {
            fail("unexpected end of input");
            return false;
        }
        const char c = s_[pos_];
        if (c == '{') return parse_object(depth, out);
        if (c == '[') return parse_array(depth, out);
        if (c == '"') {
            out.type_ = Value::Type::String;
            return parse_string(out.string_);
        }
        if (c == 't') {
            if (consume_literal("true")) {
                out.type_ = Value::Type::Bool;
                out.bool_ = true;
                return true;
            }
        } else if (c == 'f') {
            if (consume_literal("false")) {
                out.type_ = Value::Type::Bool;
                out.bool_ = false;
                return true;
            }
        } else if (c == 'n') {
            if (consume_literal("null")) {
                out.type_ = Value::Type::Null;
                return true;
            }
        } else if (c == '-' || (c >= '0' && c <= '9')) {
            return parse_number(out);
        }
        fail("invalid value");
        return false;
    }

    bool parse_number(Value& out) {
        const std::size_t start = pos_;
        bool is_int = true;
        if (s_[pos_] == '-') ++pos_;
        bool digits = false;
        while (pos_ < s_.size()) {
            const char c = s_[pos_];
            if (c >= '0' && c <= '9') {
                digits = true;
            } else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                is_int = false;
            } else {
                break;
            }
            ++pos_;
        }
        if (!digits) {
            fail("invalid number");
            return false;
        }
        const std::string_view tok = s_.substr(start, pos_ - start);
        out.type_ = Value::Type::Number;
        if (is_int) {
            // Integers (pids, timestamps) are the common case: parse without a temporary string.
            const bool neg = tok[0] == '-';
            std::uint64_t mag = 0;
            bool overflow = false;
            for (std::size_t i = neg ? 1 : 0; i < tok.size(); ++i) {
                const std::uint64_t d = static_cast<std::uint64_t>(tok[i] - '0');
                if (mag > (UINT64_MAX - d) / 10) {
                    overflow = true;
                    break;
                }
                mag = mag * 10 + d;
            }
            const std::uint64_t limit = neg ? (std::uint64_t{1} << 63) : (std::uint64_t{1} << 63) - 1;
            if (!overflow && mag <= limit) {
                const std::int64_t i =
                    neg ? (mag == (std::uint64_t{1} << 63) ? INT64_MIN : -static_cast<std::int64_t>(mag))
                        : static_cast<std::int64_t>(mag);
                out.is_int_ = true;
                out.int_ = i;
                out.double_ = static_cast<double>(i);
                return true;
            }
        }
        char buf[64];
        std::string big;
        const char* cstr = nullptr;
        if (tok.size() < sizeof(buf)) {
            std::memcpy(buf, tok.data(), tok.size());
            buf[tok.size()] = '\0';
            cstr = buf;
        } else {
            big.assign(tok);
            cstr = big.c_str();
        }
        char* end = nullptr;
        errno = 0;
        const double d = std::strtod(cstr, &end);
        if (end != cstr + tok.size()) {
            fail("invalid number");
            return false;
        }
        out.is_int_ = false;
        out.double_ = d;
        out.int_ = 0;
        return true;
    }

    static void append_utf8(std::string& out, std::uint32_t cp) {
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }

    bool parse_hex4(std::uint32_t& out) {
        if (pos_ + 4 > s_.size()) return false;
        std::uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            const char c = s_[pos_ + i];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= static_cast<std::uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') v |= static_cast<std::uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= static_cast<std::uint32_t>(c - 'A' + 10);
            else return false;
        }
        pos_ += 4;
        out = v;
        return true;
    }

    bool parse_string(std::string& out) {
        ++pos_;  // opening quote
        while (pos_ < s_.size()) {
            // Copy the run of ordinary characters in one go.
            std::size_t run = pos_;
            while (run < s_.size() && s_[run] != '"' && s_[run] != '\\') ++run;
            if (run != pos_) {
                out.append(s_.data() + pos_, run - pos_);
                pos_ = run;
                if (pos_ >= s_.size()) break;
            }
            const char c = s_[pos_++];
            if (c == '"') return true;
            if (pos_ >= s_.size()) break;
            const char e = s_[pos_++];
            switch (e) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': {
                    std::uint32_t cp = 0;
                    if (!parse_hex4(cp)) {
                        fail("invalid \\u escape");
                        return false;
                    }
                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        std::uint32_t lo = 0;
                        if (pos_ + 1 < s_.size() && s_[pos_] == '\\' && s_[pos_ + 1] == 'u') {
                            pos_ += 2;
                            if (!parse_hex4(lo) || lo < 0xDC00 || lo > 0xDFFF) {
                                fail("invalid surrogate pair");
                                return false;
                            }
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        } else {
                            fail("lone high surrogate");
                            return false;
                        }
                    }
                    append_utf8(out, cp);
                    break;
                }
                default:
                    fail("invalid escape");
                    return false;
            }
        }
        fail("unterminated string");
        return false;
    }

    bool skip_string() {
        ++pos_;
        while (pos_ < s_.size()) {
            const char ch = s_[pos_++];
            if (ch == '\\') {
                if (pos_ >= s_.size()) break;
                ++pos_;
            } else if (ch == '"') {
                return true;
            }
        }
        fail("unterminated string");
        return false;
    }

    bool skip_value(int depth) {
        if (pos_ >= s_.size()) {
            fail("unexpected end of input");
            return false;
        }
        const char c = s_[pos_];
        if (c == '"') return skip_string();
        if (c != '{' && c != '[') {
            Value scratch;
            return parse_value(depth, scratch);
        }
        int nest = 0;
        while (pos_ < s_.size()) {
            const char ch = s_[pos_];
            if (ch == '"') {
                if (!skip_string()) return false;
                continue;
            }
            if (ch == '{' || ch == '[') {
                if (depth + ++nest > kMaxDepth) {
                    fail("nesting too deep");
                    return false;
                }
            } else if (ch == '}' || ch == ']') {
                if (--nest == 0) {
                    ++pos_;
                    return true;
                }
            }
            ++pos_;
        }
        fail("unterminated value");
        return false;
    }

    bool skipped_key(std::string_view key) const {
        if (opts_ == nullptr) return false;
        for (const std::string_view k : opts_->skip_keys) {
            if (k == key) return true;
        }
        return false;
    }

    bool parse_array(int depth, Value& out) {
        ++pos_;
        out.type_ = Value::Type::Array;
        skip_ws();
        if (pos_ < s_.size() && s_[pos_] == ']') {
            ++pos_;
            return true;
        }
        out.items_.reserve(4);
        while (true) {
            skip_ws();
            out.items_.emplace_back();
            if (!parse_value(depth + 1, out.items_.back())) return false;
            skip_ws();
            if (pos_ >= s_.size()) {
                fail("unterminated array");
                return false;
            }
            if (s_[pos_] == ',') {
                ++pos_;
                continue;
            }
            if (s_[pos_] == ']') {
                ++pos_;
                return true;
            }
            fail("expected ',' or ']'");
            return false;
        }
    }

    bool parse_object(int depth, Value& out) {
        ++pos_;
        out.type_ = Value::Type::Object;
        skip_ws();
        if (pos_ < s_.size() && s_[pos_] == '}') {
            ++pos_;
            return true;
        }
        out.items_.reserve(8);
        out.keys_.reserve(8);
        while (true) {
            skip_ws();
            if (pos_ >= s_.size() || s_[pos_] != '"') {
                fail("expected object key");
                return false;
            }
            std::string key;
            if (!parse_string(key)) return false;
            skip_ws();
            if (pos_ >= s_.size() || s_[pos_] != ':') {
                fail("expected ':'");
                return false;
            }
            ++pos_;
            skip_ws();
            if (skipped_key(key)) {
                if (!skip_value(depth + 1)) return false;
                skip_ws();
                if (pos_ < s_.size() && s_[pos_] == ',') {
                    ++pos_;
                    continue;
                }
                if (pos_ < s_.size() && s_[pos_] == '}') {
                    ++pos_;
                    return true;
                }
                fail(pos_ >= s_.size() ? "unterminated object" : "expected ',' or '}'");
                return false;
            }
            // Duplicate keys: the last one wins, as before.
            std::size_t slot = out.keys_.size();
            for (std::size_t i = 0; i < out.keys_.size(); ++i) {
                if (out.keys_[i] == key) {
                    slot = i;
                    break;
                }
            }
            if (slot == out.keys_.size()) {
                out.keys_.push_back(std::move(key));
                out.items_.emplace_back();
            } else {
                out.items_[slot] = Value();
            }
            if (!parse_value(depth + 1, out.items_[slot])) return false;
            skip_ws();
            if (pos_ >= s_.size()) {
                fail("unterminated object");
                return false;
            }
            if (s_[pos_] == ',') {
                ++pos_;
                continue;
            }
            if (s_[pos_] == '}') {
                ++pos_;
                return true;
            }
            fail("expected ',' or '}'");
            return false;
        }
    }

    std::string_view s_;
    const ParseOptions* opts_ = nullptr;
    std::size_t pos_ = 0;
    std::string error_;
};

}

std::optional<Value> parse(std::string_view text, std::string* error) {
    detail::Parser p(text);
    return p.run(error);
}

std::optional<Value> parse(std::string_view text, std::string* error, const ParseOptions& options) {
    detail::Parser p(text, &options);
    return p.run(error);
}

}
