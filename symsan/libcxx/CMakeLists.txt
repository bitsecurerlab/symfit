set(SYMSAN_LIBCXX_ARCHIVES
  "${CMAKE_CURRENT_SOURCE_DIR}/build_taint/lib/libc++.a"
  "${CMAKE_CURRENT_SOURCE_DIR}/build_taint/lib/libc++abi.a"
  "${CMAKE_CURRENT_SOURCE_DIR}/build_taint/lib/libunwind.a"
)

foreach(archive ${SYMSAN_LIBCXX_ARCHIVES})
  if(EXISTS "${archive}")
    install(FILES "${archive}" DESTINATION "${SYMSAN_LIB_DIR}")
  else()
    message(STATUS "Skipping optional generated libc++ archive: ${archive}")
  endif()
endforeach()
