#include "common/json.h"

#include <cerrno>
#include <cstdlib>

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

namespace {

constexpr int kMaxDepth = 64;

class Parser {
public:
    explicit Parser(std::string_view text) : s_(text) {}

    std::optional<Value> run(std::string* error) {
        skip_ws();
        auto v = parse_value(0);
        if (v) {
            skip_ws();
            if (pos_ != s_.size()) {
                fail("unexpected trailing characters");
                v.reset();
            }
        }
        if (!v && error != nullptr) *error = error_ + " at offset " + std::to_string(pos_);
        return v;
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

    std::optional<Value> parse_value(int depth) {
        if (depth > kMaxDepth) {
            fail("nesting too deep");
            return std::nullopt;
        }
        if (pos_ >= s_.size()) {
            fail("unexpected end of input");
            return std::nullopt;
        }
        const char c = s_[pos_];
        if (c == '{') return parse_object(depth);
        if (c == '[') return parse_array(depth);
        if (c == '"') {
            std::string str;
            if (!parse_string(str)) return std::nullopt;
            return Value::make_string(std::move(str));
        }
        if (c == 't') {
            if (consume_literal("true")) return Value::make_bool(true);
        } else if (c == 'f') {
            if (consume_literal("false")) return Value::make_bool(false);
        } else if (c == 'n') {
            if (consume_literal("null")) return Value();
        } else if (c == '-' || (c >= '0' && c <= '9')) {
            return parse_number();
        }
        fail("invalid value");
        return std::nullopt;
    }

    std::optional<Value> parse_number() {
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
            return std::nullopt;
        }
        const std::string tok(s_.substr(start, pos_ - start));
        errno = 0;
        if (is_int) {
            char* end = nullptr;
            const long long i = std::strtoll(tok.c_str(), &end, 10);
            if (errno == 0 && end == tok.c_str() + tok.size()) {
                return Value::make_number(static_cast<double>(i), true, static_cast<std::int64_t>(i));
            }
            errno = 0;
        }
        char* end = nullptr;
        const double d = std::strtod(tok.c_str(), &end);
        if (end != tok.c_str() + tok.size()) {
            fail("invalid number");
            return std::nullopt;
        }
        return Value::make_number(d, false, 0);
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
            const char c = s_[pos_++];
            if (c == '"') return true;
            if (c != '\\') {
                out.push_back(c);
                continue;
            }
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

    std::optional<Value> parse_array(int depth) {
        ++pos_;
        Value arr = Value::make_array();
        skip_ws();
        if (pos_ < s_.size() && s_[pos_] == ']') {
            ++pos_;
            return arr;
        }
        while (true) {
            skip_ws();
            auto v = parse_value(depth + 1);
            if (!v) return std::nullopt;
            arr.push_back(std::move(*v));
            skip_ws();
            if (pos_ >= s_.size()) {
                fail("unterminated array");
                return std::nullopt;
            }
            if (s_[pos_] == ',') {
                ++pos_;
                continue;
            }
            if (s_[pos_] == ']') {
                ++pos_;
                return arr;
            }
            fail("expected ',' or ']'");
            return std::nullopt;
        }
    }

    std::optional<Value> parse_object(int depth) {
        ++pos_;
        Value obj = Value::make_object();
        skip_ws();
        if (pos_ < s_.size() && s_[pos_] == '}') {
            ++pos_;
            return obj;
        }
        while (true) {
            skip_ws();
            if (pos_ >= s_.size() || s_[pos_] != '"') {
                fail("expected object key");
                return std::nullopt;
            }
            std::string key;
            if (!parse_string(key)) return std::nullopt;
            skip_ws();
            if (pos_ >= s_.size() || s_[pos_] != ':') {
                fail("expected ':'");
                return std::nullopt;
            }
            ++pos_;
            skip_ws();
            auto v = parse_value(depth + 1);
            if (!v) return std::nullopt;
            obj.set(std::move(key), std::move(*v));
            skip_ws();
            if (pos_ >= s_.size()) {
                fail("unterminated object");
                return std::nullopt;
            }
            if (s_[pos_] == ',') {
                ++pos_;
                continue;
            }
            if (s_[pos_] == '}') {
                ++pos_;
                return obj;
            }
            fail("expected ',' or '}'");
            return std::nullopt;
        }
    }

    std::string_view s_;
    std::size_t pos_ = 0;
    std::string error_;
};

}

std::optional<Value> parse(std::string_view text, std::string* error) {
    Parser p(text);
    return p.run(error);
}

}
