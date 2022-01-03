from collections import defaultdict
import importlib
import json
import math
from pathlib import Path
from typing import DefaultDict, List, Optional, Set, Union, cast

import ida_typeinf
import idc
from PyQt5.QtCore import (
    QAbstractListModel,
    QModelIndex,
    QSortFilterProxyModel,
    Qt,
)
from PyQt5.QtWidgets import (
    QAction,
    QDialogButtonBox,
    QFileDialog,
    QDialog,
    QHBoxLayout,
    QLineEdit,
    QListView,
    QPushButton,
    QVBoxLayout,
    QWidget,
)
import classgen_json

importlib.reload(classgen_json)
from classgen_json import *


class Importer:
    def __init__(self):
        self.imported = set()

        self.fundamental_types = {
            "bool": ida_typeinf.BTF_BOOL,
            "void": ida_typeinf.BTF_VOID,
            # Unsigned types
            "unsigned char": ida_typeinf.BTF_UCHAR,
            "unsigned short": ida_typeinf.BTF_UINT16,
            "unsigned int": ida_typeinf.BTF_UINT32,
            "unsigned long": ida_typeinf.BTF_UINT64,
            "unsigned long long": ida_typeinf.BTF_UINT64,
            "unsigned __int128": ida_typeinf.BTF_UINT128,
            # Signed types
            "signed char": ida_typeinf.BTF_INT8,
            "signed short": ida_typeinf.BTF_INT16,
            "signed int": ida_typeinf.BTF_SINT,
            "signed long": ida_typeinf.BTF_INT64,
            "signed long long": ida_typeinf.BTF_INT64,
            "signed __int128": ida_typeinf.BTF_INT128,
            # Char types
            "char": ida_typeinf.BTF_CHAR,
            "char8_t": ida_typeinf.BTF_INT8,
            "char16_t": ida_typeinf.BTF_INT16,
            "char32_t": ida_typeinf.BT_INT32,
            "wchar_t": ida_typeinf.BTF_INT32,
            # Integer types
            "short": ida_typeinf.BTF_INT16,
            "int": ida_typeinf.BTF_INT,
            "long": ida_typeinf.BTF_INT64,
            "long long": ida_typeinf.BTF_INT64,
            "__int128": ida_typeinf.BTF_INT128,
            # Floating point types
            "float": ida_typeinf.BTF_FLOAT,
            "double": ida_typeinf.BTF_DOUBLE,
            "long double": ida_typeinf.BTF_LDOUBLE,
        }

    def import_data(
        self,
        data: TypeDump,
        prev_records: dict,
        selected: Set[str],
        skipped_types: Set[str],
    ):
        self.previous_records_by_name = prev_records
        self.enums_by_name = {e["name"]: e for e in data["enums"]}
        self.records_by_name = {e["name"]: e for e in data["records"]}
        self.skipped_types = skipped_types

        for e in data["enums"]:
            if e["name"] not in selected:
                continue

            try:
                self.import_enum(e)
            except:
                print("failed to import enum", e)
                raise

        for r in data["records"]:
            if r["name"] not in selected:
                continue

            try:
                self.import_record(r)
            except:
                print("failed to import record", r)
                raise

    def import_enum(self, data: EnumInfo):
        byte_size: int = data["underlying_type_size"]
        name: str = data["name"]
        is_scoped: bool = data["is_scoped"]

        if name in self.imported:
            return

        self.imported.add(name)

        definition = ida_typeinf.enum_type_data_t()
        definition.bte |= int(math.log2(byte_size)) + 1
        assert 1 <= byte_size <= 8
        assert definition.calc_nbytes() == byte_size

        for enumerator in data["enumerators"]:
            try:
                self._import_enum_enumerator(definition, enumerator, is_scoped, name)
            except:
                print("failed to import enumerator", enumerator)
                raise

        tinfo = ida_typeinf.tinfo_t()
        if not tinfo.create_enum(definition):
            raise RuntimeError("create_enum failed")

        self._set_named_type(tinfo, name, data)

    def _is_record_up_to_date(self, data: RecordInfo):
        name: str = data["name"]
        previous_record = self.previous_records_by_name.get(name)
        return previous_record == data

    def import_record(self, data: RecordInfo):
        name: str = data["name"]
        kind: int = data["kind"]

        if name in self.imported:
            return

        self.imported.add(name)

        if name in self.skipped_types:
            print(f"warning: skipping {name} as requested")
            return

        is_up_to_date = self._is_record_up_to_date(data)

        # Make a placeholder declaration in case the struct contains a type
        # that refers to the struct itself.
        # Example: struct Node { Node* next; };
        if not is_up_to_date:
            self._add_placeholder_record(data, name)

        definition = ida_typeinf.udt_type_data_t()
        definition.taudt_bits |= ida_typeinf.TAUDT_CPPOBJ
        definition.is_union = kind == RecordInfoKind.Union
        definition.sda = int(math.log2(data["alignment"])) + 1

        reuse_base_class_tail_padding = self._reuses_base_class_tail_padding(data)

        for field in data["fields"]:
            self._create_gap_if_needed(definition, field)
            try:
                self._import_record_field(
                    definition,
                    field,
                    name,
                    reuse_base_class_tail_padding=reuse_base_class_tail_padding,
                )
            except:
                print("failed to import field", field)
                raise

        decl_type = {
            int(RecordInfoKind.Class): ida_typeinf.BTF_STRUCT,
            int(RecordInfoKind.Struct): ida_typeinf.BTF_STRUCT,
            int(RecordInfoKind.Union): ida_typeinf.BTF_UNION,
        }[kind]

        tinfo = ida_typeinf.tinfo_t()
        if not tinfo.create_udt(definition, decl_type):
            raise RuntimeError("create_udt failed")

        if tinfo.get_size() != data["size"]:
            raise RuntimeError(
                f"size mismatch for {name}: {tinfo.get_size()} != {data['size']} (expected)"
            )

        if is_up_to_date:
            print("up-to-date: " + name)
            return

        print("importing: " + name)
        self._set_named_type(tinfo, name, data)
        self._import_record_vtable(data)

        # Unfortunately IDA does not understand that derived class members can reuse tail padding
        # from the base class, so we need to add an unaligned variant of the struct.
        #
        # Also we can't just have the aligned struct inherit the unaligned one because of
        # IDA bugs. Inheriting causes offset-to-member translations to fail for some reason.
        self._import_record_unaligned(data, decl_type)

    def _add_placeholder_record(self, data: RecordInfo, name: str):
        expected_sda = int(math.log2(data["alignment"])) + 1

        # If the type already exists and has the correct size and alignment,
        # then we have nothing to do.
        existing_type = ida_typeinf.tinfo_t()
        if existing_type.get_named_type(None, name):
            udt = ida_typeinf.udt_type_data_t()
            if (
                existing_type.get_udt_details(udt)
                and udt.size == 8 * data["size"]
                and udt.sda == expected_sda
            ):
                return

        storage_tinfo = ida_typeinf.tinfo_t(ida_typeinf.BTF_CHAR)
        if not storage_tinfo.create_array(storage_tinfo, data["size"]):
            raise RuntimeError("create_array failed")

        storage = ida_typeinf.udt_member_t()
        storage.name = "__placeholder"
        storage.type = storage_tinfo
        storage.offset = 0
        storage.size = data["size"] * 8

        udt = ida_typeinf.udt_type_data_t()
        udt.taudt_bits |= ida_typeinf.TAUDT_CPPOBJ
        udt.sda = expected_sda
        udt.push_back(storage)

        tinfo = ida_typeinf.tinfo_t()
        if not tinfo.create_udt(udt, ida_typeinf.BTF_STRUCT):
            raise RuntimeError("create_udt failed")

        self._set_named_type(tinfo, name, data)

    def _reuses_base_class_tail_padding(self, data: RecordInfo):
        """Whether this is a derived class that reuses tail padding from a base class."""
        previous_base = None
        for field in data["fields"]:
            if previous_base is not None:
                base_info = self.records_by_name[previous_base["type_name"]]
                base_offset_end = previous_base["offset"] + base_info["size"]
                if field["offset"] < base_offset_end:
                    return True

            if field["kind"] == "base":
                previous_base = field

        return False

    def _create_gap_if_needed(
        self, definition: ida_typeinf.udt_type_data_t, field: FieldInfoUnion
    ):
        if definition.empty():
            return

        last_field: ida_typeinf.udt_member_t = definition.back()
        # In bits.
        gap_offset: int = last_field.offset + last_field.size
        gap_size: int = field["offset"] * 8 - gap_offset

        if gap_size <= 0:
            return

        gap = ida_typeinf.udt_member_t()
        gap.name = f"gap{gap_offset // 8:X}"
        gap.size = gap_size
        gap.offset = gap_offset
        gap_type = ida_typeinf.tinfo_t()
        if not gap_type.create_array(
            ida_typeinf.tinfo_t(ida_typeinf.BTF_CHAR), gap_size // 8
        ):
            raise RuntimeError("failed to create array for gap")
        gap.type = gap_type
        definition.push_back(gap)

    def _import_record_unaligned(self, data: RecordInfo, decl_type):
        name: str = self._get_unaligned_struct_name(data["name"])
        kind: int = data["kind"]

        definition = ida_typeinf.udt_type_data_t()
        definition.taudt_bits |= ida_typeinf.TAUDT_CPPOBJ
        definition.taudt_bits |= ida_typeinf.TAUDT_UNALIGNED
        definition.is_union = kind == RecordInfoKind.Union
        definition.sda = 0

        reuse_base_class_tail_padding = self._reuses_base_class_tail_padding(data)

        for field in data["fields"]:
            # Create gaps manually because we can't rely on IDA to do it for us.
            self._create_gap_if_needed(definition, field)

            try:
                self._import_record_field(
                    definition,
                    field,
                    name,
                    reuse_base_class_tail_padding=reuse_base_class_tail_padding,
                )
            except:
                print("failed to import field", field)
                raise

        tinfo = ida_typeinf.tinfo_t()
        if not tinfo.create_udt(definition, decl_type):
            raise RuntimeError("create_udt failed")

        self._set_named_type(tinfo, name, data)

    def _import_enum_by_name(self, name: str):
        data = self.enums_by_name.get(name)
        if data is not None:
            self.import_enum(data)

    def _import_record_by_name(self, name: str):
        if name in self.imported:
            return

        data = self.records_by_name.get(name)
        if data is not None:
            self.import_record(data)
        else:
            # Create an empty struct.
            print("warning: creating empty struct for " + name)
            self.imported.add(name)
            udt = ida_typeinf.udt_type_data_t()
            tinfo = ida_typeinf.tinfo_t()
            if not tinfo.create_udt(udt, ida_typeinf.BTF_STRUCT):
                raise RuntimeError("create_udt failed")
            self._set_named_type(tinfo, name, name)

    def _import_enum_enumerator(
        self,
        definition: ida_typeinf.enum_type_data_t,
        enumerator: EnumEnumeratorInfo,
        is_scoped: bool,
        name: str,
    ):
        member_name: str = enumerator["identifier"]
        if is_scoped:
            member_name = name + "::" + member_name

        member = ida_typeinf.enum_member_t()
        member.name = member_name
        member.value = int(enumerator["value"])
        definition.push_back(member)

    def _set_named_type(self, tinfo: ida_typeinf.tinfo_t, name: str, data):
        if name.startswith("("):
            name = "__" + name

        ret = tinfo.set_named_type(None, name, ida_typeinf.NTF_REPLACE)
        if ret != ida_typeinf.TERR_OK:
            raise RuntimeError("set_named_type failed", ret, data)

    def _import_record_field(
        self,
        definition: ida_typeinf.udt_type_data_t,
        field: FieldInfoUnion,
        record_name: str,
        reuse_base_class_tail_padding: bool,
    ):
        member = ida_typeinf.udt_member_t()
        member.offset = field["offset"] * 8

        if field["kind"] == "member":
            member.name = field["name"]
            member.type = self._get_complex_type(field["type"])

        elif field["kind"] == "base":
            base_name: str = field["type_name"]

            member.name = "baseclass_" + str(field["offset"])
            member.type = self._get_type_by_name(base_name)
            if reuse_base_class_tail_padding:
                member.type = self._get_type_by_name(
                    self._get_unaligned_struct_name(base_name)
                )

            member.set_baseclass()

            if field["is_virtual"]:
                member.set_virtbase()

        elif field["kind"] == "vtable_ptr":
            vtable_type = self._get_ptr_to_type(
                self._get_vtable_struct_name(record_name)
            )

            member.name = "__vftable"
            member.type = vtable_type
            member.set_vftable()

        else:
            raise ValueError("unexpected field kind", field)

        assert member.type is not None, ("failed to set type", record_name, field)

        member_size = member.type.get_size()
        if member_size == ida_typeinf.BADSIZE:
            raise ValueError("bad size")

        member.size = 8 * member_size

        definition.push_back(member)

    def _import_record_vtable(self, data: RecordInfo):
        vtable = data.get("vtable")
        if vtable is None:
            return

        name: str = data["name"]
        vtable_name: str = self._get_vtable_struct_name(name)

        this_type = self._get_type_by_name(name)
        assert this_type is not None
        this_type.create_ptr(this_type)

        # Counts the number of functions with the same name.
        # Necessary to fix name conflicts when a virtual function is overloaded.
        name_counts: DefaultDict[str, int] = defaultdict(int)

        definition = ida_typeinf.udt_type_data_t()
        definition.taudt_bits |= ida_typeinf.TAUDT_CPPOBJ

        imported_one_func = False
        offset = 0
        for component in vtable:
            if component["kind"] == "vcall_offset":
                if imported_one_func:
                    self._import_vtable_uintptr_t(definition, offset, component["kind"])
                continue

            if component["kind"] == "vbase_offset":
                if imported_one_func:
                    self._import_vtable_uintptr_t(definition, offset, component["kind"])
                continue

            if component["kind"] == "offset_to_top":
                if imported_one_func:
                    if component["offset"] != 0:
                        break
                    self._import_vtable_uintptr_t(definition, offset, component["kind"])
                continue

            if component["kind"] == "rtti":
                if imported_one_func:
                    self._import_vtable_uintptr_t(
                        definition, offset, component["kind"], ptr=True
                    )
                continue

            imported_one_func = True

            if component["kind"] == "func":
                self._import_record_vtable_fn(
                    definition, this_type, component, offset, name_counts
                )

            elif component["kind"] == "complete_dtor":
                self._import_record_vtable_fn(
                    definition, this_type, component, offset, name_counts
                )

            elif component["kind"] == "deleting_dtor":
                self._import_record_vtable_fn(
                    definition, this_type, component, offset, name_counts
                )

            else:
                raise ValueError("unexpected vtable component kind", component)

            offset += 8

        tinfo = ida_typeinf.tinfo_t()
        if not tinfo.create_udt(definition, ida_typeinf.BTF_STRUCT):
            raise RuntimeError("vtable create_udt failed", data)

        self._set_named_type(tinfo, vtable_name, data)

    def _import_vtable_uintptr_t(
        self,
        definition: ida_typeinf.udt_type_data_t,
        offset: int,
        description: str,
        ptr=False,
    ):
        member = ida_typeinf.udt_member_t()
        member.name = f"{description}_{offset}"
        if ptr:
            t = ida_typeinf.tinfo_t(ida_typeinf.BTF_VOID)
            t.create_ptr(t)
            member.type = t
        else:
            member.type = self._get_type_by_name("long")
        member.size = 8 * 8
        member.offset = offset * 8
        definition.push_back(member)

    def _import_record_vtable_fn(
        self,
        definition: ida_typeinf.udt_type_data_t,
        this_type: ida_typeinf.tinfo_t,
        component: Union[
            VTableComponentFuncInfo,
            VTableComponentDeletingDtorInfo,
            VTableComponentCompleteDtorInfo,
        ],
        offset: int,
        name_counts: DefaultDict[str, int],
    ):
        kind: str = component["kind"]

        name = component["function_name"]
        if kind == "complete_dtor":
            name = "dtor"
        elif kind == "deleting_dtor":
            name = "dtorDelete"

        if component["is_thunk"]:
            adj = f"{component['this_adjustment']:#x}"
            adj = adj.replace("-", "m")
            name += f"__thunk_{adj}"

        func_tinfo = self._get_complex_type(component["type"], this_type)
        if not func_tinfo.is_func():
            raise RuntimeError("unexpected tinfo type for function", func_tinfo)
        if not func_tinfo.create_ptr(func_tinfo):
            raise RuntimeError("failed to create tinfo for function")

        member = ida_typeinf.udt_member_t()
        if name not in name_counts:
            member.name = name
        else:
            member.name = f"{name}__{name_counts[name]}"
        name_counts[name] += 1
        member.cmt = component["repr"]
        member.type = func_tinfo
        member.size = 8 * 8
        member.offset = offset * 8

        definition.push_back(member)

    def _get_type_by_name(self, name: str) -> ida_typeinf.tinfo_t:
        orig_name = name

        # IDA dislikes names starting with (
        if name.startswith("("):
            name = "__" + name

        make_volatile = False
        if name.startswith("_Atomic(") and name.endswith(")"):
            name = name[len("_Atomic(") : -1]
            make_volatile = True

        fundamental_type = self.fundamental_types.get(name)
        if fundamental_type is not None:
            return ida_typeinf.tinfo_t(fundamental_type)

        # FIXME: this is ugly.
        if name == "__attribute__((__vector_size__(4 * sizeof(float)))) float":
            return self._get_type_by_name("float32x4_t")

        # This check ensures that dependencies are re-imported
        # from the type dump even if they already exist in IDA.
        if orig_name in self.enums_by_name:
            self._import_enum_by_name(orig_name)
        if orig_name in self.records_by_name:
            self._import_record_by_name(orig_name)

        tinfo = ida_typeinf.tinfo_t()
        if not tinfo.get_named_type(None, name):
            # This check must happen after get_named_types to avoid
            # extra empty structs being created in some cases(?)
            self._import_record_by_name(orig_name)
            if not tinfo.get_named_type(None, name):
                raise KeyError(name)

        if make_volatile:
            tinfo.set_volatile()

        return tinfo

    def _get_complex_type(
        self,
        t: ComplexTypeUnion,
        func_this_type: Optional[ida_typeinf.tinfo_t] = None,
    ) -> ida_typeinf.tinfo_t:
        if t["kind"] == "pointer":
            pointee_type = cast(ComplexTypeUnion, t["pointee_type"])
            pointee_tinfo = self._get_complex_type(pointee_type)

            tinfo = ida_typeinf.tinfo_t()
            if not tinfo.create_ptr(pointee_tinfo):
                raise RuntimeError("create_ptr failed")
            return tinfo

        if t["kind"] == "array":
            element_type = cast(ComplexTypeUnion, t["element_type"])
            element_tinfo = self._get_complex_type(element_type)

            tinfo = ida_typeinf.tinfo_t()
            if not tinfo.create_array(element_tinfo, t["size"]):
                raise RuntimeError("create_array failed")
            return tinfo

        if t["kind"] == "function":
            param_types = cast(List[ComplexTypeUnion], t["param_types"])
            return_type = cast(ComplexTypeUnion, t["return_type"])

            func = ida_typeinf.func_type_data_t()
            func.cc = ida_typeinf.CM_CC_FASTCALL
            func.rettype = self._get_complex_type(return_type)

            if func_this_type is not None:
                arg = ida_typeinf.funcarg_t()
                arg.name = "this"
                arg.type = func_this_type
                arg.flags |= ida_typeinf.FAI_HIDDEN
                func.push_back(arg)

            for param_type in param_types:
                arg = ida_typeinf.funcarg_t()
                arg.type = self._get_complex_type(param_type)
                func.push_back(arg)

            tinfo = ida_typeinf.tinfo_t()
            if not tinfo.create_func(func):
                raise RuntimeError("create_func failed")
            return tinfo

        if t["kind"] == "member_pointer":
            class_type = cast(ComplexTypeUnion, t["class_type"])
            pointee_type = cast(ComplexTypeUnion, t["pointee_type"])

            class_tinfo = self._get_complex_type(class_type)

            this_type = ida_typeinf.tinfo_t()
            if not this_type.create_ptr(class_tinfo):
                raise ValueError("create_ptr failed", t)

            pointee_tinfo = self._get_complex_type(pointee_type, this_type)
            if not pointee_tinfo.is_func():
                # Data member pointers are represented using a ptrdiff_t.
                return self._get_type_by_name("long")

            # Member function pointers are represented as a struct { fn_ptr, adj };
            ptmf_struct_name = t["repr"]
            tinfo = ida_typeinf.tinfo_t()
            if tinfo.get_named_type(None, ptmf_struct_name) and tinfo.is_struct():
                return tinfo

            # The struct doesn't exist -- create it.
            udt = ida_typeinf.udt_type_data_t()

            fn_ptr = ida_typeinf.udt_member_t()
            fn_ptr.name = "ptr"
            fn_ptr_tinfo = ida_typeinf.tinfo_t()
            if not fn_ptr_tinfo.create_ptr(pointee_tinfo):
                raise RuntimeError("create_ptr failed")
            fn_ptr.type = fn_ptr_tinfo
            fn_ptr.offset = 0 * 8
            fn_ptr.size = 8 * 8
            udt.push_back(fn_ptr)

            adj = ida_typeinf.udt_member_t()
            adj.name = "adj"
            adj.type = self._get_type_by_name("long")
            adj.offset = 8 * 8
            adj.size = 8 * 8
            udt.push_back(adj)

            tinfo = ida_typeinf.tinfo_t()
            if not tinfo.create_udt(udt, ida_typeinf.BTF_STRUCT):
                raise RuntimeError("failed to create PTMF struct")

            self._set_named_type(tinfo, ptmf_struct_name, t)
            return self._get_type_by_name(ptmf_struct_name)

        if t["kind"] == "type_name":
            return self._get_type_by_name(t["name"])

        raise ValueError("unexpected complex type kind", t)

    def _get_ptr_to_type(self, name: str) -> ida_typeinf.tinfo_t:
        tinfo = ida_typeinf.tinfo_t()
        if tinfo.get_named_type(None, name) and tinfo.create_ptr(tinfo):
            return tinfo

        tinfo = ida_typeinf.tinfo_t()

        ret = tinfo.create_forward_decl(None, ida_typeinf.BTF_STRUCT, name)
        if ret != ida_typeinf.TERR_OK:
            raise RuntimeError("create_forward_decl failed", name, ret)

        if not tinfo.create_ptr(tinfo):
            raise ValueError("create_ptr failed")

        return tinfo

    def _get_vtable_struct_name(self, record_name: str) -> str:
        if record_name.startswith("$$"):
            return record_name[2:] + "_vtbl"

        # This is imposed by IDA
        return record_name + "_vtbl"

    def _get_unaligned_struct_name(self, record_name: str) -> str:
        return "$$" + record_name


class EnumListModel(QAbstractListModel):
    def __init__(self, data: TypeDump):
        super().__init__()
        self.type_data = data

    def rowCount(self, parent):
        return len(self.type_data["enums"])

    def data(self, index: QModelIndex, role: int):
        row = index.row()
        entry = self.type_data["enums"][row]
        if role == Qt.ItemDataRole.DisplayRole:
            return f"Enum: {entry['name']}"
        if role == Qt.ItemDataRole.UserRole:
            return entry["name"]


class RecordListModel(QAbstractListModel):
    def __init__(self, data: TypeDump):
        super().__init__()
        self.type_data = data

    def rowCount(self, parent):
        return len(self.type_data["records"])

    def data(self, index: QModelIndex, role: int):
        row = index.row()
        entry = self.type_data["records"][row]
        if role == Qt.ItemDataRole.DisplayRole:
            return f"Record: {entry['name']}"
        if role == Qt.ItemDataRole.UserRole:
            return entry["name"]


# Unfortunately IDA's bundled copy of PyQt doesn't have QConcatenateTablesProxyModel.
class ConcatenateListProxyModel(QAbstractListModel):
    def __init__(self):
        super().__init__()
        self.models: List[QAbstractListModel] = []

    def rowCount(self, parent: QModelIndex) -> int:
        return sum(model.rowCount(parent) for model in self.models)

    def data(self, index: QModelIndex, role: int):
        base = 0
        for model in self.models:
            real_row = index.row() - base
            if real_row < model.rowCount(index):
                return model.data(self.index(real_row, 0), role=role)
            base += model.rowCount(index)
        return None


class TypeListModel(ConcatenateListProxyModel):
    def __init__(self, data: TypeDump):
        super().__init__()
        self.checked = defaultdict(bool)
        self.models.append(EnumListModel(data))
        self.models.append(RecordListModel(data))

    def data(self, index: QModelIndex, role: int):
        if role == Qt.ItemDataRole.CheckStateRole:
            key = super().data(index, role=Qt.ItemDataRole.UserRole)
            checked = self.checked[key]
            return Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked

        return super().data(index, role=role)

    def setData(self, index: QModelIndex, value, role: int) -> bool:
        if role == Qt.ItemDataRole.CheckStateRole:
            key = super().data(index, role=Qt.ItemDataRole.UserRole)
            self.checked[key] = value == Qt.CheckState.Checked
            self.dataChanged.emit(index, index)
            return True

        return super().setData(index, value, role=role)

    def flags(self, index: QModelIndex) -> Qt.ItemFlags:
        return super().flags(index) | Qt.ItemFlag.ItemIsUserCheckable


class TypeChooser(QDialog):
    def __init__(self, data: TypeDump):
        super().__init__()
        self.setWindowTitle("Choose types to import")
        self.resize(1000, 800)

        self.model = TypeListModel(data)
        proxy_model = QSortFilterProxyModel()
        proxy_model.setSourceModel(self.model)
        proxy_model.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

        view = self.view = QListView()
        view.setModel(proxy_model)

        all_btn = QPushButton("&All")
        all_btn.clicked.connect(self.on_all)
        none_btn = QPushButton("&None")
        none_btn.clicked.connect(self.on_none)

        filter_edit = QLineEdit()
        filter_edit.setPlaceholderText("Filter...")
        filter_edit.textChanged.connect(proxy_model.setFilterFixedString)

        filter_bar = QHBoxLayout()
        filter_bar.addWidget(all_btn)
        filter_bar.addWidget(none_btn)
        filter_bar.addWidget(filter_edit, stretch=1)
        filter_bar_widget = QWidget()
        filter_bar_widget.setLayout(filter_bar)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)

        layout = QVBoxLayout()
        layout.addWidget(view, stretch=1)
        layout.addWidget(filter_bar_widget)
        layout.addWidget(button_box)
        self.setLayout(layout)

        filter_action = QAction(self)
        filter_action.setShortcut("ctrl+f")
        filter_action.triggered.connect(lambda: filter_edit.setFocus())
        self.addAction(filter_action)

    def get_selected(self) -> Set[str]:
        result = set()
        for k, checked in self.model.checked.items():
            if checked:
                result.add(k)
        return result

    def on_all(self, checked):
        model: QAbstractListModel = self.view.model()
        for row in range(model.rowCount(model.index(0, 0))):
            idx = model.index(row, 0)
            model.setData(idx, Qt.CheckState.Checked, Qt.ItemDataRole.CheckStateRole)

    def on_none(self, checked):
        model: QAbstractListModel = self.view.model()
        for row in range(model.rowCount(model.index(0, 0))):
            idx = model.index(row, 0)
            model.setData(idx, Qt.CheckState.Unchecked, Qt.ItemDataRole.CheckStateRole)


def main() -> None:
    idb_path: str = idc.get_idb_path()
    if not idb_path:
        raise RuntimeError("failed to get IDB path")

    path, _ = QFileDialog.getOpenFileName(None, "Select a type dump", "", "*.json")
    if not path:
        return

    print(f"importing type dump: {path}")

    with open(path, "rb") as f:
        data: TypeDump = json.load(f)

    prev_records = dict()
    prev_records_path = Path(idb_path + ".imported")
    try:
        with prev_records_path.open("rb") as f:
            prev_records = json.load(f)
    except:
        pass

    skipped_types: Set[str] = set()
    try:
        with Path(idb_path + ".skip").open("r") as f:
            for line in f:
                skipped_types.add(line.strip())
    except IOError:
        pass

    chooser = TypeChooser(data)
    result = chooser.exec_()
    if result == QDialog.Rejected:
        print("type chooser cancelled")
        return
    selected = chooser.get_selected()

    importer = Importer()
    importer.import_data(data, prev_records, selected, skipped_types)

    # Update the imported types database.
    for e in data["records"]:
        if e["name"] in importer.imported:
            prev_records[e["name"]] = e
    with prev_records_path.open("w") as f:
        json.dump(prev_records, f)


if __name__ == "__main__":
    main()
