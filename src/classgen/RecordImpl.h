// Copyright (c) 2021 leoetlino
// SPDX-License-Identifier: MIT

#pragma once

#include <memory>

namespace clang {
class ASTContext;
class EnumDecl;
class RecordDecl;
}  // namespace clang

namespace classgen {

struct ParseConfig;
struct ParseResult;

class ParseContext {
public:
  static std::unique_ptr<ParseContext> Make(ParseResult& result, const ParseConfig& config);

  virtual ~ParseContext();

  virtual void HandleEnumDecl(clang::EnumDecl* D) = 0;
  virtual void HandleRecordDecl(clang::RecordDecl* D) = 0;

  ParseResult& GetResult() const { return m_result; }

protected:
  explicit ParseContext(ParseResult& result, const ParseConfig& config)
      : m_result(result), m_config(config) {}

  ParseResult& m_result;
  const ParseConfig& m_config;
};

}  // namespace classgen
