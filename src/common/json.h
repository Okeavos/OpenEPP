#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sec::json {

// Small read-only JSON document model (enough for rule files and sensor output).
class Value {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    Value() = default;

    static Value make_bool(bool b);
    static Value make_number(double d, bool is_int, std::int64_t i);
    static Value make_string(std::string s);
    static Value make_array();
    static Value make_object();

    Type type() const { return type_; }
    bool is_null() const { return type_ == Type::Null; }
    bool is_bool() const { return type_ == Type::Bool; }
    bool is_number() const { return type_ == Type::Number; }
    bool is_string() const { return type_ == Type::String; }
    bool is_array() const { return type_ == Type::Array; }
    bool is_object() const { return type_ == Type::Object; }

    bool as_bool(bool fallback = false) const;
    double as_double(double fallback = 0.0) const;
    std::int64_t as_int(std::int64_t fallback = 0) const;
    // Empty string unless this is a string.
    const std::string& as_string() const;

    // Array elements, or object values (aligned with keys()).
    const std::vector<Value>& items() const { return items_; }
    const std::vector<std::string>& keys() const { return keys_; }
    std::size_t size() const { return items_.size(); }

    // Object lookup; nullptr if missing or not an object.
    const Value* find(std::string_view key) const;
    // Object lookup that yields a shared null Value when missing.
    const Value& operator[](std::string_view key) const;
    const Value& operator[](std::size_t index) const;

    void push_back(Value v);
    void set(std::string key, Value v);

private:
    static const Value& null_value();

    Type type_ = Type::Null;
    bool bool_ = false;
    double double_ = 0.0;
    std::int64_t int_ = 0;
    bool is_int_ = false;
    std::string string_;
    std::vector<Value> items_;
    std::vector<std::string> keys_;
};

// Parses a complete JSON document. On failure returns nullopt and fills *error (if given).
std::optional<Value> parse(std::string_view text, std::string* error = nullptr);

}
