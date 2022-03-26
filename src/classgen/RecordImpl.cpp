// Copyright (c) 2021 leoetlino
// SPDX-License-Identifier: MIT

#include "classgen/RecordImpl.h"
#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/AST/Expr.h>
#include <clang/AST/PrettyPrinter.h>
#include <clang/AST/RecordLayout.h>
#include <clang/AST/VTableBuilder.h>
#include <clang/Basic/Thunk.h>
#include <fmt/format.h>
#include <llvm/ADT/STLExtras.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/StringSet.h>
#include "classgen/ComplexType.h"
#include "classgen/Record.h"

namespace classgen {

namespace {

std::string_view GetCStyleOperatorName(const clang::CXXMethodDecl* func) {
  if (!func->isOverloadedOperator())
    return "";

  switch (func->getOverloadedOperator()) {
  case clang::OO_None:
    break;
  case clang::OO_New:
    return "__op_new";
  case clang::OO_Delete:
    return "__op_delete";
  case clang::OO_Array_New:
    return "__op_array_new";
  case clang::OO_Array_Delete:
    return "__op_array_delete";
  case clang::OO_Plus:
    return "__op_plus";
  case clang::OO_Minus:
    return "__op_minus";
  case clang::OO_Star:
    return "__op_star";
  case clang::OO_Slash:
    return "__op_slash";
  case clang::OO_Percent:
    return "__op_percent";
  case clang::OO_Caret:
    return "__op_caret";
  case clang::OO_Amp:
    return "__op_amp";
  case clang::OO_Pipe:
    return "__op_pipe";
  case clang::OO_Tilde:
    return "__op_tilde";
  case clang::OO_Exclaim:
    return "__op_exclaim";
  case clang::OO_Equal:
    return "__op_eq";
  case clang::OO_Less:
    return "__op_lt";
  case clang::OO_Greater:
    return "__op_gt;";
  case clang::OO_PlusEqual:
    return "__op_plus_equal";
  case clang::OO_MinusEqual:
    return "__op_minus_equal";
  case clang::OO_StarEqual:
    return "__op_star_equal";
  case clang::OO_SlashEqual:
    return "__op_slash_equal";
  case clang::OO_PercentEqual:
    return "__op_percent_equal";
  case clang::OO_CaretEqual:
    return "__op_caret_equal";
  case clang::OO_AmpEqual:
    return "__op_amp_equal";
  case clang::OO_PipeEqual:
    return "__op_pipe_equal";
  case clang::OO_LessLess:
    return "__op_lt_lt";
  case clang::OO_GreaterGreater:
    return "__op_gt_gt";
  case clang::OO_LessLessEqual:
    return "__op_lt_lt_eq";
  case clang::OO_GreaterGreaterEqual:
    return "__op_gt_gt_eq";
  case clang::OO_EqualEqual:
    return "__op_eq_eq";
  case clang::OO_ExclaimEqual:
    return "__op_exclaim_eq";
  case clang::OO_LessEqual:
    return "__op_leq";
  case clang::OO_GreaterEqual:
    return "__op_geq";
  case clang::OO_Spaceship:
    return "__op_spaceship";
  case clang::OO_AmpAmp:
    return "__op_amp_amp";
  case clang::OO_PipePipe:
    return "__op_pipe_pipe";
  case clang::OO_PlusPlus:
    return "__op_plus_plus";
  case clang::OO_MinusMinus:
    return "__op_minus_minus";
  case clang::OO_Comma:
    return "__op_comma";
  case clang::OO_ArrowStar:
    return "__op_arrow_star";
  case clang::OO_Arrow:
    return "__op_arrow";
  case clang::OO_Call:
    return "__op_call";
  case clang::OO_Subscript:
    return "__op_subscript";
  case clang::OO_Conditional:
    return "__op_conditional";
  case clang::OO_Coawait:
    return "__op_coawait";
  case clang::NUM_OVERLOADED_OPERATORS:
    break;
  }

  return "";
}

std::unique_ptr<ComplexType> TranslateToComplexType(clang::QualType type, clang::ASTContext& ctx,
                                                    const clang::PrintingPolicy& policy) {
  type = type.getCanonicalType();

  if (const auto* array = ctx.getAsConstantArrayType(type)) {
    return std::make_unique<ComplexTypeArray>(
        TranslateToComplexType(array->getElementType(), ctx, policy),
        array->getSize().getZExtValue());
  }

  if (const auto* ptr = type->getAs<clang::MemberPointerType>()) {
    return std::make_unique<ComplexTypeMemberPointer>(
        TranslateToComplexType(ptr->getClass()->getCanonicalTypeInternal(), ctx, policy),
        TranslateToComplexType(ptr->getPointeeType(), ctx, policy), type.getAsString(policy));
  }

  if (const auto* ptr = type->getAs<clang::PointerType>()) {
    return std::make_unique<ComplexTypePointer>(
        TranslateToComplexType(ptr->getPointeeType(), ctx, policy));
  }

  if (const auto* ref = type->getAs<clang::ReferenceType>()) {
    return std::make_unique<ComplexTypePointer>(
        TranslateToComplexType(ref->getPointeeType(), ctx, policy));
  }

  if (const auto* prototype = type->getAs<clang::FunctionProtoType>()) {
    const llvm::ArrayRef<clang::QualType> param_types = prototype->getParamTypes();

    std::vector<std::unique_ptr<ComplexType>> params;
    params.reserve(param_types.size());
    for (clang::QualType param_type : param_types)
      params.emplace_back(TranslateToComplexType(param_type, ctx, policy));

    auto return_type = TranslateToComplexType(prototype->getReturnType(), ctx, policy);
    return std::make_unique<ComplexTypeFunction>(std::move(params), std::move(return_type));
  }

  if (const auto* atomic = type->getAs<clang::AtomicType>()) {
    return std::make_unique<ComplexTypeAtomic>(
        TranslateToComplexType(atomic->getValueType(), ctx, policy));
  }

  const bool is_const = type.isConstQualified();
  const bool is_volatile = type.isVolatileQualified();
  type.removeLocalFastQualifiers();
  return std::make_unique<ComplexTypeName>(type.getAsString(policy), is_const, is_volatile);
}

const clang::ThunkInfo* GetThunkInfo(const clang::VTableLayout& layout, std::size_t idx) {
  const auto thunks = layout.vtable_thunks();

  // Search for a matching ThunkInfo by doing a binary search.
  auto it = llvm::lower_bound(thunks, idx,
                              [](const auto& entry, std::size_t key) { return entry.first < key; });

  if (it == thunks.end())
    return nullptr;

  if (it->first != idx)
    return nullptr;

  return &it->second;
}

std::unique_ptr<VTable> ParseVTable(const clang::CXXRecordDecl* D) {
  clang::ASTContext& ctx = D->getASTContext();
  clang::VTableContextBase* vtable_ctx_base = ctx.getVTableContext();

  auto* vtable_ctx = dyn_cast<clang::ItaniumVTableContext>(vtable_ctx_base);
  if (!vtable_ctx) {
    // Only the Itanium ABI is supported.
    return {};
  }

  if (!D->isDynamicClass())
    return {};

  const clang::VTableLayout& layout = vtable_ctx->getVTableLayout(D);

  const clang::PrintingPolicy policy{D->getLangOpts()};

  // Copy component data from the layout.
  auto vtable = std::make_unique<VTable>();
  vtable->components.reserve(layout.vtable_components().size());
  for (const auto& pair : llvm::enumerate(layout.vtable_components())) {
    const auto idx = pair.index();
    const clang::VTableComponent& component = pair.value();

    switch (component.getKind()) {
    case clang::VTableComponent::CK_VCallOffset: {
      vtable->components.emplace_back(VTableComponent::VCallOffset{
          .offset = component.getVCallOffset().getQuantity(),
      });
      break;
    }

    case clang::VTableComponent::CK_VBaseOffset: {
      vtable->components.emplace_back(VTableComponent::VBaseOffset{
          .offset = component.getVBaseOffset().getQuantity(),
      });
      break;
    }

    case clang::VTableComponent::CK_OffsetToTop: {
      vtable->components.emplace_back(VTableComponent::OffsetToTop{
          .offset = component.getOffsetToTop().getQuantity(),
      });
      break;
    }

    case clang::VTableComponent::CK_RTTI: {
      auto* type = component.getRTTIDecl();
      vtable->components.emplace_back(VTableComponent::RTTI{
          .class_name = ctx.getTypeDeclType(type).getAsString(policy),
      });
      break;
    }

    case clang::VTableComponent::CK_FunctionPointer:
    case clang::VTableComponent::CK_CompleteDtorPointer:
    case clang::VTableComponent::CK_DeletingDtorPointer:
    case clang::VTableComponent::CK_UnusedFunctionPointer: {
      auto* func = component.getFunctionDecl();
      std::string name{func->getName()};

      if (name.empty() && func->isOverloadedOperator()) {
        name = GetCStyleOperatorName(func);
      }

      // Build the user-friendly name.
      std::string repr =
          clang::PredefinedExpr::ComputeName(clang::PredefinedExpr::PrettyFunctionNoVirtual, func);

      if (component.getKind() == clang::VTableComponent::CK_CompleteDtorPointer)
        repr += " [complete]";

      if (component.getKind() == clang::VTableComponent::CK_DeletingDtorPointer)
        repr += " [deleting]";

      if (func->isPure())
        repr += " [pure]";

      // Figure out if this is a thunk. This logic is based on Clang's ItaniumVTableBuilder.
      const auto* thunk = GetThunkInfo(layout, idx);

      if (thunk && !thunk->isEmpty()) {
        if (!thunk->Return.isEmpty()) {
          repr += fmt::format(" [return adjustment: {:#x}", thunk->Return.NonVirtual);

          if (thunk->Return.Virtual.Itanium.VBaseOffsetOffset != 0) {
            repr += fmt::format(", vbase offset offset: {:#x}",
                                thunk->Return.Virtual.Itanium.VBaseOffsetOffset);
          }

          repr += ']';
        }

        if (!thunk->This.isEmpty()) {
          repr += fmt::format(" [this adjustment: {:#x}", thunk->This.NonVirtual);

          if (thunk->This.Virtual.Itanium.VCallOffsetOffset != 0) {
            repr += fmt::format(", vcall offset offset: {:#x}",
                                thunk->This.Virtual.Itanium.VCallOffsetOffset);
          }

          repr += ']';
        }
      }

      auto entry = VTableComponent::FunctionPointer{
          .is_const = func->isConst(),
          .repr = std::move(repr),
          .function_name = std::move(name),
          .type = TranslateToComplexType(func->getType(), ctx, policy),
      };

      // Fill thunk information if necessary.
      if (thunk && !thunk->isEmpty()) {
        entry.is_thunk = true;

        if (!thunk->Return.isEmpty()) {
          entry.return_adjustment = thunk->Return.NonVirtual;
          entry.return_adjustment_vbase_offset_offset =
              thunk->Return.Virtual.Itanium.VBaseOffsetOffset;
        }

        if (!thunk->This.isEmpty()) {
          entry.this_adjustment = thunk->This.NonVirtual;
          entry.this_adjustment_vcall_offset_offset = thunk->This.Virtual.Itanium.VCallOffsetOffset;
        }
      }

      switch (component.getKind()) {
      case clang::VTableComponent::CK_FunctionPointer:
      case clang::VTableComponent::CK_UnusedFunctionPointer:
        vtable->components.emplace_back(std::move(entry));
        break;
      case clang::VTableComponent::CK_CompleteDtorPointer:
        vtable->components.emplace_back(VTableComponent::CompleteDtorPointer{std::move(entry)});
        break;
      case clang::VTableComponent::CK_DeletingDtorPointer:
        vtable->components.emplace_back(VTableComponent::DeletingDtorPointer{{std::move(entry)}});
        break;
      default:
        llvm_unreachable("unexpected component kind");
        break;
      }

      break;
    }
    }
  }

  return vtable;
}

class ParseContextImpl final : public ParseContext {
public:
  explicit ParseContextImpl(ParseResult& result, const ParseConfig& config)
      : ParseContext(result, config) {}

  void HandleEnumDecl(clang::EnumDecl* D) override {
    D = D->getDefinition();
    if (!CanProcess(D))
      return;

    const clang::ASTContext& ctx = D->getASTContext();
    const clang::PrintingPolicy policy{D->getLangOpts()};

    const clang::QualType underlying_type = D->getIntegerType().getCanonicalType();

    Enum& enum_def = m_result.enums.emplace_back();
    enum_def.is_scoped = D->isScoped();
    enum_def.is_anonymous = D->getName().empty();
    enum_def.name = ctx.getTypeDeclType(D).getAsString(policy);
    enum_def.underlying_type_name = underlying_type.getAsString(policy);
    enum_def.underlying_type_size = ctx.getTypeSizeInChars(underlying_type).getQuantity();

    for (const clang::EnumConstantDecl* decl : D->enumerators()) {
      Enum::Enumerator& entry = enum_def.enumerators.emplace_back();

      entry.identifier = decl->getNameAsString();

      llvm::SmallVector<char> value;
      decl->getInitVal().toString(value);
      entry.value.insert(entry.value.begin(), value.begin(), value.end());
    }
  }

  void HandleRecordDecl(clang::RecordDecl* D) override {
    D = D->getDefinition();
    if (!CanProcess(D))
      return;

    auto* CXXRD = dyn_cast<clang::CXXRecordDecl>(D);

    const clang::ASTContext& ctx = D->getASTContext();
    const clang::PrintingPolicy policy{D->getLangOpts()};
    const clang::ASTRecordLayout& layout = ctx.getASTRecordLayout(D);

    if (ShouldInlineEmptyRecord(D))
      return;

    Record& record = m_result.records.emplace_back();

    record.is_anonymous = D->isAnonymousStructOrUnion();
    record.kind = [&] {
      switch (D->getTagKind()) {
      case clang::TTK_Struct:
        return Record::Kind::Struct;
      case clang::TTK_Interface:
      case clang::TTK_Class:
        return Record::Kind::Class;
      case clang::TTK_Union:
        return Record::Kind::Union;
      case clang::TTK_Enum:
        break;
      }
      return Record::Kind::Struct;
    }();
    record.name = ctx.getTypeDeclType(D).getAsString(policy);
    record.size = layout.getSize().getQuantity();
    record.data_size = layout.getDataSize().getQuantity();
    record.alignment = layout.getAlignment().getQuantity();

    AddFields(record, clang::CharUnits::Zero(), D, layout, policy);

    if (CXXRD)
      record.vtable = ParseVTable(CXXRD);
  }

private:
  bool CanProcess(const clang::TagDecl* D) {
    if (!D)
      return false;

    if (D->isInvalidDecl())
      return false;

    if (!D->isCompleteDefinition())
      return false;

    if (D->isTemplated()) {
      // For templated classes, we only care about instantiations.
      // isTemplated() returns false for ClassTemplateSpecializationDecl.
      return false;
    }

    const clang::ASTContext& ctx = D->getASTContext();
    const clang::PrintingPolicy policy{D->getLangOpts()};
    const auto name = ctx.getTypeDeclType(D).getAsString(policy);

    if (m_processed.contains(name))
      return false;

    m_processed.insert(name);
    return true;
  }

  void AddBases(Record& record, clang::CharUnits base_offset, const clang::CXXRecordDecl* CXXRD,
                const clang::ASTRecordLayout& layout, const clang::PrintingPolicy& policy) {
    if (!CXXRD)
      return;

    const clang::ASTContext& ctx = CXXRD->getASTContext();

    // Collect base classes. This logic mostly mirrors Clang's RecordLayoutBuilder.
    const clang::CXXRecordDecl* primary_base = layout.getPrimaryBase();

    // Vtable pointer.
    if (CXXRD->isDynamicClass() && primary_base == nullptr) {
      Field& field = record.fields.emplace_back();
      field.offset = base_offset.getQuantity();
      field.data = Field::VTablePointer();
    }

    // Non-virtual bases.
    llvm::SmallVector<const clang::CXXRecordDecl*, 5> bases;
    for (const clang::CXXBaseSpecifier& base : CXXRD->bases()) {
      if (!base.isVirtual())
        bases.push_back(base.getType()->getAsCXXRecordDecl());
    }

    llvm::stable_sort(bases, [&](const clang::CXXRecordDecl* L, const clang::CXXRecordDecl* R) {
      return layout.getBaseClassOffset(L) < layout.getBaseClassOffset(R);
    });

    for (const clang::CXXRecordDecl* base : bases) {
      const auto offset = base_offset + layout.getBaseClassOffset(base);

      if (ShouldInlineEmptyRecord(base))
        continue;

      Field& field = record.fields.emplace_back();
      field.offset = offset.getQuantity();
      field.data = Field::Base{
          .is_primary = base == primary_base,
          .is_virtual = false,
          .type_name = ctx.getTypeDeclType(base).getAsString(policy),
      };
    }
  }

  void AddVirtualBases(Record& record, clang::CharUnits base_offset,
                       const clang::CXXRecordDecl* CXXRD, const clang::ASTRecordLayout& layout,
                       const clang::PrintingPolicy& policy) {
    if (!CXXRD)
      return;

    const clang::ASTContext& ctx = CXXRD->getASTContext();
    const clang::CXXRecordDecl* primary_base = layout.getPrimaryBase();

    llvm::SmallVector<const clang::CXXRecordDecl*, 5> vbases;
    vbases.reserve(CXXRD->getNumVBases());
    for (const clang::CXXBaseSpecifier& specifier : CXXRD->vbases()) {
      auto* base = specifier.getType()->getAsCXXRecordDecl();
      vbases.push_back(base);
    }

    llvm::stable_sort(vbases, [&](const clang::CXXRecordDecl* L, const clang::CXXRecordDecl* R) {
      return layout.getVBaseClassOffset(L) < layout.getVBaseClassOffset(R);
    });

    for (const clang::CXXRecordDecl* base : vbases) {
      const auto offset = base_offset + layout.getVBaseClassOffset(base);

      if (ShouldInlineEmptyRecord(base))
        continue;

      Field& field = record.fields.emplace_back();
      field.offset = offset.getQuantity();
      field.data = Field::Base{
          .is_primary = base == primary_base,
          .is_virtual = true,
          .type_name = ctx.getTypeDeclType(base).getAsString(policy),
      };
    }
  }

  void AddDataMembers(Record& record, clang::CharUnits base_offset, const clang::RecordDecl* D,
                      const clang::ASTRecordLayout& layout, const clang::PrintingPolicy& policy) {
    clang::ASTContext& ctx = D->getASTContext();

    uint64_t field_idx = 0;
    for (const clang::FieldDecl* field_decl : D->fields()) {
      // Unnamed bitfields are not members.
      if (field_decl->isUnnamedBitfield())
        continue;

      const auto rel_offset_in_bits = layout.getFieldOffset(field_idx++);
      const auto offset =
          base_offset + ctx.toCharUnitsFromBits(static_cast<int64_t>(rel_offset_in_bits));

      // Is this a record?
      if (auto* field_record = field_decl->getType()->getAsRecordDecl()) {
        if (D->isUnion() || !ShouldInlineEmptyRecord(field_record)) {
          Field& field = record.fields.emplace_back();
          field.offset = offset.getQuantity();
          field.data = Field::MemberVariable{
              .type = TranslateToComplexType(ctx.getTypeDeclType(field_record), ctx, policy),
              .type_name = ctx.getTypeDeclType(field_record).getAsString(policy),
              .name = field_decl->getNameAsString(),
          };
        }
        continue;
      }

      Field& field = record.fields.emplace_back();
      field.offset = offset.getQuantity();
      field.data = Field::MemberVariable{
          .bitfield_width = field_decl->isBitField() ? field_decl->getBitWidthValue(ctx) : 0,
          .type = TranslateToComplexType(field_decl->getType(), ctx, policy),
          .type_name = field_decl->getType().getCanonicalType().getAsString(policy),
          .name = field_decl->getNameAsString(),
      };
    }
  }

  void AddFields(Record& record, clang::CharUnits base_offset, const clang::RecordDecl* D,
                 const clang::ASTRecordLayout& layout, const clang::PrintingPolicy& policy) {
    auto* CXXRD = dyn_cast<clang::CXXRecordDecl>(D);

    AddBases(record, base_offset, CXXRD, layout, policy);
    AddDataMembers(record, base_offset, D, layout, policy);
    AddVirtualBases(record, base_offset, CXXRD, layout, policy);
  }

  /// Returns whether D is an empty record that should be inlined.
  bool ShouldInlineEmptyRecord(const clang::RecordDecl* D) const {
    if (!m_config.inline_empty_structs)
      return false;

    clang::ASTContext& ctx = D->getASTContext();
    const clang::ASTRecordLayout& layout = ctx.getASTRecordLayout(D);

    if (layout.getDataSize().isZero())
      return true;

    // Sometimes empty structs (e.g. struct Foo {};) will still have a data size of one.
    // In that case we need to check whether the struct is empty manually.
    auto* CXXRD = dyn_cast<clang::CXXRecordDecl>(D);
    if (!CXXRD)
      return true;

    // No vtables, no bases, no virtual bases, no fields.
    return !CXXRD->isDynamicClass() && CXXRD->bases().empty() && CXXRD->vbases().empty() &&
           !CXXRD->hasDirectFields();
  }

  llvm::StringSet<> m_processed;
};

}  // namespace

ParseContext::~ParseContext() = default;

std::unique_ptr<ParseContext> ParseContext::Make(ParseResult& result, const ParseConfig& config) {
  return std::make_unique<ParseContextImpl>(result, config);
}

}  // namespace classgen
