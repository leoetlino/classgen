add_library(classgen
  ../../include/classgen/ComplexType.h
  ../../include/classgen/Record.h
  Record.cpp
  RecordImpl.cpp
  RecordImpl.h
)

target_include_directories(classgen PUBLIC ../../include/)
target_include_directories(classgen PRIVATE ../)
target_compile_options(classgen PRIVATE -fno-exceptions)
if (NOT LLVM_ENABLE_RTTI)
  target_compile_options(classgen PRIVATE -fno-rtti)
endif()

target_link_libraries(classgen PRIVATE clangAST clangTooling)
target_link_libraries(classgen PRIVATE fmt)
