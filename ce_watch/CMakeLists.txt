find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(CAPSTONE QUIET capstone)
endif()

add_executable(ce_watch
    main.cpp
    Watcher.cpp
)

set_target_properties(ce_watch PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

target_include_directories(ce_watch PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(ce_watch PRIVATE _GNU_SOURCE)

if(CAPSTONE_FOUND)
    target_include_directories(ce_watch PRIVATE ${CAPSTONE_INCLUDE_DIRS})
    target_link_directories(ce_watch PRIVATE ${CAPSTONE_LIBRARY_DIRS})
    target_link_libraries(ce_watch PRIVATE ${CAPSTONE_LIBRARIES})
    target_compile_definitions(ce_watch PRIVATE HAVE_CAPSTONE=1)
endif()

add_executable(test_target
    test_target.c
)
