add_executable(classgen-dump DumpTool.cpp)
target_link_libraries(classgen-dump PRIVATE classgen)
target_link_libraries(classgen-dump PRIVATE clangAST clangTooling)

if (NOT LLVM_ENABLE_RTTI)
  target_compile_options(classgen-dump PRIVATE -fno-rtti)
endif()
