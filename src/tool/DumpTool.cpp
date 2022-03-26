// Copyright (c) 2021 leoetlino
// SPDX-License-Identifier: MIT

#include <clang/Frontend/FrontendActions.h>
#include <clang/Tooling/CommonOptionsParser.h>
#include <clang/Tooling/Tooling.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/JSON.h>
#include "classgen/Record.h"

namespace cl = llvm::cl;

static cl::OptionCategory MyToolCategory("classgen options");
static cl::extrahelp CommonHelp(clang::tooling::CommonOptionsParser::HelpMessage);
static cl::opt<bool> OptInlineEmptyStructs{"i", cl::desc("inline empty structs"),
                                           cl::cat(MyToolCategory)};

// must be called inside an object block
static void DumpComplexType(llvm::json::OStream& out, const classgen::ComplexType& type) {
  const auto write_common = [&](llvm::StringRef kind) { out.attribute("kind", kind); };

  switch (type.GetKind()) {
  case classgen::ComplexType::Kind::TypeName: {
    const auto& name = static_cast<const classgen::ComplexTypeName&>(type);
    write_common("type_name");
    out.attribute("name", name.name);
    out.attribute("is_const", name.is_const);
    out.attribute("is_volatile", name.is_volatile);
    break;
  }

  case classgen::ComplexType::Kind::Pointer: {
    const auto& ptr = static_cast<const classgen::ComplexTypePointer&>(type);
    write_common("pointer");
    out.attributeObject("pointee_type", [&] { DumpComplexType(out, *ptr.pointee_type); });
    break;
  }

  case classgen::ComplexType::Kind::Array: {
    const auto& array = static_cast<const classgen::ComplexTypeArray&>(type);
    write_common("array");
    out.attributeObject("element_type", [&] { DumpComplexType(out, *array.element_type); });
    out.attribute("size", array.size);
    break;
  }

  case classgen::ComplexType::Kind::Function: {
    const auto& fn = static_cast<const classgen::ComplexTypeFunction&>(type);
    write_common("function");

    out.attributeArray("param_types", [&] {
      for (const auto& param_type : fn.param_types)
        out.object([&] { DumpComplexType(out, *param_type); });
    });

    out.attributeObject("return_type", [&] { DumpComplexType(out, *fn.return_type); });
    break;
  }

  case classgen::ComplexType::Kind::MemberPointer: {
    const auto& ptr = static_cast<const classgen::ComplexTypeMemberPointer&>(type);
    write_common("member_pointer");
    out.attributeObject("class_type", [&] { DumpComplexType(out, *ptr.class_type); });
    out.attributeObject("pointee_type", [&] { DumpComplexType(out, *ptr.pointee_type); });
    out.attribute("repr", ptr.repr);
    break;
  }

  case classgen::ComplexType::Kind::Atomic: {
    const auto& ptr = static_cast<const classgen::ComplexTypeAtomic&>(type);
    write_common("atomic");
    out.attributeObject("value_type", [&] { DumpComplexType(out, *ptr.value_type); });
    break;
  }
  }
}

// must be called inside an object block
static void DumpEnum(llvm::json::OStream& out, const classgen::Enum& enum_def) {
  out.attribute("is_scoped", enum_def.is_scoped);
  out.attribute("is_anonymous", enum_def.is_anonymous);
  out.attribute("name", enum_def.name);
  out.attribute("underlying_type_name", enum_def.underlying_type_name);
  out.attribute("underlying_type_size", enum_def.underlying_type_size);

  out.attributeArray("enumerators", [&] {
    for (const classgen::Enum::Enumerator& entry : enum_def.enumerators) {
      out.object([&] {
        out.attribute("identifier", entry.identifier);
        out.attribute("value", entry.value);
      });
    }
  });
}

// must be called inside an object block
static void DumpVTableFunction(llvm::json::OStream& out,
                               const classgen::VTableComponent::FunctionPointer& func) {
  out.attribute("is_thunk", func.is_thunk);
  out.attribute("is_const", func.is_const);

  if (func.is_thunk) {
    out.attribute("return_adjustment", func.return_adjustment);
    out.attribute("return_adjustment_vbase_offset_offset",
                  func.return_adjustment_vbase_offset_offset);

    out.attribute("this_adjustment", func.this_adjustment);
    out.attribute("this_adjustment_vcall_offset_offset", func.this_adjustment_vcall_offset_offset);
  }

  out.attribute("repr", func.repr);
  out.attribute("function_name", func.function_name);
  out.attributeObject("type", [&] { DumpComplexType(out, *func.type); });
}

// must be called inside an object block
static void DumpRecord(llvm::json::OStream& out, const classgen::Record& record) {
  out.attribute("is_anonymous", record.is_anonymous);
  out.attribute("kind", int(record.kind));
  out.attribute("name", record.name);
  out.attribute("size", record.size);
  out.attribute("data_size", record.data_size);
  out.attribute("alignment", record.alignment);

  out.attributeArray("fields", [&] {
    for (const classgen::Field& field : record.fields) {
      // must be called inside an object block
      const auto write_common = [&](llvm::StringRef kind) {
        out.attribute("offset", field.offset);
        out.attribute("kind", kind);
      };

      if (auto* member = std::get_if<classgen::Field::MemberVariable>(&field.data)) {
        out.object([&] {
          write_common("member");
          if (member->bitfield_width != 0)
            out.attribute("bitfield_width", member->bitfield_width);
          out.attributeObject("type", [&] { DumpComplexType(out, *member->type); });
          out.attribute("type_name", member->type_name);
          out.attribute("name", member->name);
        });
        continue;
      }

      if (auto* base = std::get_if<classgen::Field::Base>(&field.data)) {
        out.object([&] {
          write_common("base");
          out.attribute("is_primary", base->is_primary);
          out.attribute("is_virtual", base->is_virtual);
          out.attribute("type_name", base->type_name);
        });
        continue;
      }

      if (auto* vtable_ptr = std::get_if<classgen::Field::VTablePointer>(&field.data)) {
        out.object([&] {
          write_common("vtable_ptr");
          // No other attributes.
        });
      }
    }
  });

  if (record.vtable) {
    out.attributeArray("vtable", [&] {
      for (const classgen::VTableComponent& component : record.vtable->components) {
        // must be called inside an object block
        const auto write_common = [&](llvm::StringRef kind) { out.attribute("kind", kind); };

        if (auto* vcallo = std::get_if<classgen::VTableComponent::VCallOffset>(&component.data)) {
          out.object([&] {
            write_common("vcall_offset");
            out.attribute("offset", vcallo->offset);
          });
          continue;
        }

        if (auto* vbaseo = std::get_if<classgen::VTableComponent::VBaseOffset>(&component.data)) {
          out.object([&] {
            write_common("vbase_offset");
            out.attribute("offset", vbaseo->offset);
          });
          continue;
        }

        if (auto* offset = std::get_if<classgen::VTableComponent::OffsetToTop>(&component.data)) {
          out.object([&] {
            write_common("offset_to_top");
            out.attribute("offset", offset->offset);
          });
          continue;
        }

        if (auto* rtti = std::get_if<classgen::VTableComponent::RTTI>(&component.data)) {
          out.object([&] {
            write_common("rtti");
            out.attribute("class_name", rtti->class_name);
          });
          continue;
        }

        if (auto* func = std::get_if<classgen::VTableComponent::FunctionPointer>(&component.data)) {
          out.object([&] {
            write_common("func");
            DumpVTableFunction(out, *func);
          });
          continue;
        }

        if (auto* complete_dtor =
                std::get_if<classgen::VTableComponent::CompleteDtorPointer>(&component.data)) {
          out.object([&] {
            write_common("complete_dtor");
            DumpVTableFunction(out, *complete_dtor);
          });
          continue;
        }

        if (auto* deleting_dtor =
                std::get_if<classgen::VTableComponent::DeletingDtorPointer>(&component.data)) {
          out.object([&] {
            write_common("deleting_dtor");
            DumpVTableFunction(out, *deleting_dtor);
          });
          continue;
        }
      }
    });
  } else {
    out.attribute("vtable", nullptr);
  }
}

int main(int argc, const char** argv) {
  auto MaybeOptionsParser = clang::tooling::CommonOptionsParser::create(argc, argv, MyToolCategory);
  if (!MaybeOptionsParser)
    return 1;

  auto& OptionsParser = MaybeOptionsParser.get();

  clang::tooling::ClangTool Tool(OptionsParser.getCompilations(),
                                 OptionsParser.getSourcePathList());

  classgen::ParseConfig config;
  config.inline_empty_structs = OptInlineEmptyStructs.getValue();

  const auto result = classgen::ParseRecords(Tool, config);

  if (!result.error.empty()) {
    llvm::errs() << result.error << '\n';
  }

  llvm::json::OStream out(llvm::outs());

  out.object([&] {
    out.attributeArray("enums", [&] {
      for (const classgen::Enum& enum_def : result.enums)
        out.object([&] { DumpEnum(out, enum_def); });
    });

    out.attributeArray("records", [&] {
      for (const classgen::Record& record : result.records)
        out.object([&] { DumpRecord(out, record); });
    });
  });

  return 0;
}
