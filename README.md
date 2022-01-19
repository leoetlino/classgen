classgen
========

Small Clang-based tool to dump type information (enums, records, vtables) from a C++ codebase.

## Prerequisites

- A compiler that supports C++20
- CMake 3.16+
- LLVM + Clang
  - Version 13 and 14 are known to work; other versions are untested.

## Building from source

1. `git clone https://github.com/leoetlino/classgen`
2. `mkdir build` then `cd build`
3. `cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo`
    * This will automatically locate an existing install of LLVM.
    * If you compiled Clang from source, add `-DCMAKE_PREFIX_PATH=/path/to/llvm-project/build/lib/cmake`
    * If you are using a pre-built release from [releases.llvm.org](https://releases.llvm.org/), add `-DCMAKE_PREFIX_PATH=/path/to/extracted/archive/lib/cmake`
4. `cmake --build .`

## Usage

### Generating type dumps

Use `classgen-dump` to generate a JSON type dump that can be imported into other tools:

```
classgen-dump [source files...] [options] > output.json
```

If you have a [compilation database](https://clang.llvm.org/docs/JSONCompilationDatabase.html) for your project, you can pass `-p [path to database or build dir]` to tell classgen-dump to load compilation flags from the database.

Useful options:

* `-i`: Inline empty structs. If passed, record types that are empty (no fields, no bases, no vtables) will be folded into their containing records. This helps reduce the number of records in the output -- typically this will prevent things like `std::integral_constant<int, 42>` from appearing in the record list.

* You can pass compilation options with `-- [options]`, the same way you'd specify options to Clang. For example:

```
classgen-dump hello.cpp -- -target aarch64-none-elf -march=armv8-a+crc+crypto -std=c++20 [etc.]
```

### Visualising type dumps

Type dumps can be easily visualised using a simple web-based viewer app (viewer.html). You can find an online (but possibly outdated) version of the viewer at https://botw.link/classgen-viewer

### Importing a type dump into IDA

To import a type dump into an IDA database, just run the `ida/classgen_load.py` script (requires IDAPython).

Partial type imports are supported -- you can choose which types to import. Please note that importing a struct will recursively import all of its dependencies (member field types, pointer types, member function return types, etc.) *Warning: Any type that already exists will be overwritten*.

Known issues:

* Importing types on older databases can sometimes cause existing types to break. This is because of IDA bugs or because your types are defined incorrectly. If you are importing a type that already exists in your database, make sure that it has the correct size and alignment.

* IDA <= 7.6 does not understand that class tail padding can be reused for derived class data members. To work around this shortcoming, the type importer creates two structs for every record you're importing: one with the correct alignment/sizeof, and another one with the "packed" attribute and with a `$$` name prefix. If necessary, the importer will use the packed version to represent class inheritance -- this causes ugly casts when upcasting but it is the only way to get the correct object layout under IDA's current type model.

#### Speeding up imports

To avoid useless re-imports, the IDA script keeps track of type definitions that have already been imported into the IDB. The type record is stored in a JSON file next to the IDB with the `.imported` file extension suffix.

If you want to force a type to be imported (e.g. because you have manually edited a struct in IDA and classgen isn't detecting the change), just tick the "Force re-import" checkbox when importing.

As yet another import time optimisation, it is possible to specify a list of types that will *never* be imported; instead, classgen will assume that they already exist in the IDB and will never attempt to create or update them. Simply create a text file next to the IDB with the `.skip` file extension suffix, and write each type that should be skipped on its own line.
