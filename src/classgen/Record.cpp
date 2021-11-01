// Copyright (c) 2021 leoetlino
// SPDX-License-Identifier: MIT

#include "classgen/Record.h"
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Basic/TargetInfo.h>
#include <clang/Frontend/FrontendAction.h>
#include <clang/Tooling/CompilationDatabase.h>
#include <clang/Tooling/Tooling.h>
#include "classgen/RecordImpl.h"

namespace classgen {

namespace {

class ParseRecordConsumer final : public clang::ASTConsumer,
                                  public clang::RecursiveASTVisitor<ParseRecordConsumer> {
public:
  explicit ParseRecordConsumer(ParseContext& context) : m_parse_context(context) {}

  void HandleTranslationUnit(clang::ASTContext& Ctx) override {
    if (!Ctx.getTargetInfo().getCXXABI().isItaniumFamily()) {
      m_parse_context.GetResult().error = "only the Itanium C++ ABI is supported";
      return;
    }

    TraverseAST(Ctx);
  }

  bool VisitEnumDecl(clang::EnumDecl* D) {
    m_parse_context.HandleEnumDecl(D);
    return true;
  }

  bool VisitRecordDecl(clang::RecordDecl* D) {
    m_parse_context.HandleRecordDecl(D);
    return true;
  }

  bool shouldVisitTemplateInstantiations() const { return true; }

private:
  ParseContext& m_parse_context;
};

class ParseRecordAction final : public clang::ASTFrontendAction {
public:
  explicit ParseRecordAction(ParseContext& context) : m_context(context) {}

protected:
  std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(clang::CompilerInstance& CI,
                                                        llvm::StringRef InFile) override {
    return std::make_unique<ParseRecordConsumer>(m_context);
  }

private:
  ParseContext& m_context;
};

class ParseRecordActionFactory final : public clang::tooling::FrontendActionFactory {
public:
  explicit ParseRecordActionFactory(ParseContext& context) : m_context(context) {}

  std::unique_ptr<clang::FrontendAction> create() override {
    return std::make_unique<ParseRecordAction>(m_context);
  }

  ParseContext& m_context;
};

}  // namespace

ParseResult ParseRecords(clang::tooling::ClangTool& tool, const ParseConfig& config) {
  ParseResult result;
  auto context = ParseContext::Make(result, config);
  ParseRecordActionFactory factory{*context};
  if (tool.run(&factory) != 0) {
    result.AddErrorContext("failed to run tool");
  }
  return result;
}

ParseResult ParseRecords(std::string_view build_dir, std::span<const std::string> source_files,
                         const ParseConfig& config) {
  std::string compilation_db_error;
  auto compilation_db =
      clang::tooling::CompilationDatabase::loadFromDirectory(build_dir, compilation_db_error);
  if (!compilation_db) {
    return ParseResult::Fail("failed to create compilation database: " + compilation_db_error);
  }

  clang::tooling::ClangTool tool{*compilation_db, {source_files.data(), source_files.size()}};
  return ParseRecords(tool, config);
}

}  // namespace classgen
