// Copyright (c) 2021 leoetlino
// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <classgen/ComplexType.h>

namespace clang::tooling {
class ClangTool;
}

namespace classgen {

struct Enum {
  struct Enumerator {
    std::string identifier;
    std::string value;
  };

  bool is_scoped{};
  bool is_anonymous{};
  std::uint8_t underlying_type_size{};
  std::string name;
  std::string underlying_type_name;
  std::vector<Enumerator> enumerators;
};

struct VTableComponent {
  struct VCallOffset {
    std::int64_t offset{};
  };

  struct VBaseOffset {
    std::int64_t offset{};
  };

  struct OffsetToTop {
    std::int64_t offset{};
  };

  struct RTTI {
    std::string class_name;
  };

  struct FunctionPointer {
    /// Whether this function is a thunk.
    bool is_thunk = false;
    /// Whether this is a const member function.
    bool is_const = false;
    /// [Thunks] [Itanium ABI] Return adjustment.
    std::int64_t return_adjustment = 0;
    /// [Thunks] [Itanium ABI] Return adjustment vbase offset offset.
    std::int64_t return_adjustment_vbase_offset_offset = 0;
    /// [Thunks] [Itanium ABI] This pointer adjustment.
    std::int64_t this_adjustment = 0;
    /// [Thunks] [Itanium ABI] This pointer adjustment vcall offset offset.
    std::int64_t this_adjustment_vcall_offset_offset = 0;

    /// A human-readable description, e.g. `bool Foo::f() const`
    std::string repr;
    /// e.g. `f`. Empty for destructors.
    std::string function_name;
    /// Type.
    std::unique_ptr<ComplexType> type;
  };

  struct CompleteDtorPointer : FunctionPointer {};

  struct DeletingDtorPointer : CompleteDtorPointer {};

  using Data = std::variant<VCallOffset, VBaseOffset, OffsetToTop, RTTI, FunctionPointer,
                            CompleteDtorPointer, DeletingDtorPointer>;

  // NOLINTNEXTLINE(google-explicit-constructor)
  VTableComponent(Data data_) : data(std::move(data_)) {}

  Data data;
};

struct VTable {
  std::vector<VTableComponent> components;
};

struct Field {
  struct MemberVariable {
    /// 0 if this is not a bitfield.
    unsigned int bitfield_width{};
    std::unique_ptr<ComplexType> type;
    std::string type_name;
    std::string name;
  };

  struct Base {
    bool is_primary = false;
    bool is_virtual = false;
    std::string type_name;
  };

  struct VTablePointer {};

  /// Offset since the beginning of the record.
  std::size_t offset{};
  /// Type-specific data.
  std::variant<std::monostate, MemberVariable, Base, VTablePointer> data;
};

struct Record {
  enum class Kind {
    Class,
    Struct,
    Union,
  };

  /// Whether this is an anonymous record.
  bool is_anonymous{};
  /// Kind.
  Kind kind{};
  /// Fully qualified name.
  std::string name;
  /// sizeof() in bytes.
  std::size_t size{};
  /// Data size in bytes (size without tail padding).
  std::size_t data_size{};
  /// Alignment in bytes.
  std::size_t alignment{};
  /// Record fields (e.g. member variables).
  /// Note that base classes are also represented as fields.
  std::vector<Field> fields;
  /// Associated virtual function table. Might be nullptr if this record has no vtable.
  std::unique_ptr<VTable> vtable;
};

struct ParseResult {
  ParseResult() = default;

  static ParseResult Fail(std::string error_) {
    ParseResult result;
    result.error = std::move(error_);
    return result;
  }

  void AddErrorContext(const std::string& error_) {
    error = error_ + (error.empty() ? "" : ": ") + error;
  }

  explicit operator bool() const { return error.empty(); }

  std::string error;
  std::vector<Enum> enums;
  std::vector<Record> records;
};

struct ParseConfig {
  /// Whether empty structs should be inlined into any containing record.
  bool inline_empty_structs = false;
};

ParseResult ParseRecords(clang::tooling::ClangTool& tool, const ParseConfig& config = {});
ParseResult ParseRecords(std::string_view build_dir, std::span<const std::string> source_files,
                         const ParseConfig& config = {});

}  // namespace classgen
