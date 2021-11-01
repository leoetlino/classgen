from enum import IntEnum
from typing import List, Literal, Optional, TypedDict, Union


class EnumEnumeratorInfo(TypedDict):
    identifier: str
    value: int


class EnumInfo(TypedDict):
    is_scoped: bool
    is_anonymous: bool
    name: str
    underlying_type_name: str
    underlying_type_size: int
    enumerators: List[EnumEnumeratorInfo]


class ComplexTypeInfo(TypedDict):
    pass


class ComplexTypeNameInfo(ComplexTypeInfo):
    kind: Literal["type_name"]
    name: str


class ComplexTypePointerInfo(ComplexTypeInfo):
    kind: Literal["pointer"]
    pointee_type: ComplexTypeInfo


class ComplexTypeArrayInfo(ComplexTypeInfo):
    kind: Literal["array"]
    element_type: ComplexTypeInfo
    size: int


class ComplexTypeFunctionInfo(ComplexTypeInfo):
    kind: Literal["function"]
    param_types: List[ComplexTypeInfo]
    return_type: ComplexTypeInfo


class ComplexTypeMemberPointerInfo(ComplexTypeInfo):
    kind: Literal["member_pointer"]
    class_type: ComplexTypeInfo
    pointee_type: ComplexTypeInfo
    repr: str


ComplexTypeUnion = Union[
    ComplexTypeNameInfo,
    ComplexTypePointerInfo,
    ComplexTypeArrayInfo,
    ComplexTypeFunctionInfo,
    ComplexTypeMemberPointerInfo,
]


class VTableComponentInfo(TypedDict):
    ...


class VTableComponentVCallOffsetInfo(VTableComponentInfo):
    kind: Literal["vcall_offset"]
    offset: int


class VTableComponentVBaseOffsetInfo(VTableComponentInfo):
    kind: Literal["vbase_offset"]
    offset: int


class VTableComponentOffsetToTopInfo(VTableComponentInfo):
    kind: Literal["offset_to_top"]
    offset: int


class VTableComponentRTTIInfo(VTableComponentInfo):
    kind: Literal["rtti"]
    class_name: str


class VTableComponentFuncInfoBase(VTableComponentInfo):
    is_thunk: bool
    repr: str
    function_name: str
    type: ComplexTypeUnion

    # only present if is_thunk is true
    return_adjustment: int
    return_adjustment_vbase_offset_offset: int
    this_adjustment: int
    this_adjustment_vcall_offset_offset: int


class VTableComponentFuncInfo(VTableComponentFuncInfoBase):
    kind: Literal["func"]


class VTableComponentCompleteDtorInfo(VTableComponentFuncInfoBase):
    kind: Literal["complete_dtor"]


class VTableComponentDeletingDtorInfo(VTableComponentFuncInfoBase):
    kind: Literal["deleting_dtor"]


VTableComponentInfoUnion = Union[
    VTableComponentVBaseOffsetInfo,
    VTableComponentVCallOffsetInfo,
    VTableComponentRTTIInfo,
    VTableComponentFuncInfo,
    VTableComponentCompleteDtorInfo,
    VTableComponentDeletingDtorInfo,
]


class FieldInfo(TypedDict):
    offset: int


class MemberFieldInfo(FieldInfo):
    kind: Literal["member"]
    bitfield_width: Optional[int]
    type: ComplexTypeUnion
    type_name: str
    name: str


class BaseFieldInfo(FieldInfo):
    kind: Literal["base"]
    is_primary: bool
    is_virtual: bool
    type_name: str


class VTablePtrFieldInfo(FieldInfo):
    kind: Literal["vtable_ptr"]


FieldInfoUnion = Union[MemberFieldInfo, BaseFieldInfo, VTablePtrFieldInfo]


class RecordInfoKind(IntEnum):
    Class = 0
    Struct = 1
    Union = 2


class RecordInfo(TypedDict):
    is_anonymous: bool
    kind: RecordInfoKind
    name: str
    size: int
    data_size: int
    alignment: int
    fields: List[FieldInfoUnion]
    vtable: Optional[List[VTableComponentInfoUnion]]


class TypeDump(TypedDict):
    enums: List[EnumInfo]
    records: List[RecordInfo]
