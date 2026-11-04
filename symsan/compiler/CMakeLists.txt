add_executable(KOClang ko_clang.c)
list(GET LLVM_INCLUDE_DIRS 0 SYMSAN_LLVM_INCLUDE_DIR)
target_compile_definitions(KOClang PRIVATE
  SYMSAN_LLVM_INCLUDE_DIR="${SYMSAN_LLVM_INCLUDE_DIR}")
set_target_properties(KOClang PROPERTIES OUTPUT_NAME "ko-clang")

add_custom_command(TARGET KOClang POST_BUILD
    COMMAND ln -sf "ko-clang" "ko-clang++")
install (TARGETS KOClang DESTINATION ${SYMSAN_BIN_DIR})
install (FILES ${CMAKE_CURRENT_BINARY_DIR}/ko-clang++ DESTINATION ${SYMSAN_BIN_DIR})
