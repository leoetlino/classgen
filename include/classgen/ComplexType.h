#pragma once

#include <memory>
#include <string>
#include <vector>

namespace classgen {

/// Represents a slightly C-ified type.
///
/// For instance, sead::SafeStringBase<char>* [3] is decomposed as
/// Array[ Pointer[ TypeName[sead::SafeStringBase<char>] ], 3]
/// (note how sead::SafeStringBase<char> is not further decomposed).
///
/// References are transformed into pointers and qualifiers are not kept (except in strings).
class ComplexType {
public:
  enum class Kind {
    TypeName,
    Pointer,
    Array,
    Function,
    MemberPointer,
  };

  virtual ~ComplexType() = default;
  Kind GetKind() const { return m_kind; }

protected:
  explicit ComplexType(Kind kind) : m_kind(kind) {}

  Kind m_kind;
};

class ComplexTypeName final : public ComplexType {
public:
  explicit ComplexTypeName(std::string name_)
      : ComplexType(Kind::TypeName), name(std::move(name_)) {}

  std::string name;
};

class ComplexTypePointer final : public ComplexType {
public:
  explicit ComplexTypePointer(std::unique_ptr<ComplexType> pointee_type_)
      : ComplexType(Kind::Pointer), pointee_type(std::move(pointee_type_)) {}

  std::unique_ptr<ComplexType> pointee_type;
};

class ComplexTypeArray final : public ComplexType {
public:
  explicit ComplexTypeArray(std::unique_ptr<ComplexType> element_type_, std::uint64_t size_)
      : ComplexType(Kind::Array), element_type(std::move(element_type_)), size(size_) {}

  std::unique_ptr<ComplexType> element_type;
  std::uint64_t size{};
};

class ComplexTypeFunction final : public ComplexType {
public:
  explicit ComplexTypeFunction(std::vector<std::unique_ptr<ComplexType>> param_types_,
                               std::unique_ptr<ComplexType> return_type_)
      : ComplexType(Kind::Function), param_types(std::move(param_types_)),
        return_type(std::move(return_type_)) {}

  std::vector<std::unique_ptr<ComplexType>> param_types;
  std::unique_ptr<ComplexType> return_type;
};

/// Represents a pointer-to-member (data or function).
/// Note that a pointer-to-member is *not* actually a pointer and
/// the in-memory representation usually differs.
class ComplexTypeMemberPointer final : public ComplexType {
public:
  explicit ComplexTypeMemberPointer(std::unique_ptr<ComplexType> class_type_,
                                    std::unique_ptr<ComplexType> pointee_type_, std::string repr_)
      : ComplexType(Kind::MemberPointer), class_type(std::move(class_type_)),
        pointee_type(std::move(pointee_type_)), repr(std::move(repr_)) {}

  std::unique_ptr<ComplexType> class_type;
  std::unique_ptr<ComplexType> pointee_type;
  std::string repr;
};

}  // namespace classgen
