set(SRC
    main.cpp
    gui/MainWindow.cpp
    gui/ProcessListModel.cpp
    gui/ProcessDialog.cpp
    gui/PointerScannerDialog.cpp
    gui/AutoAssemblerDialog.cpp
    gui/MemoryViewerWindow.cpp
    gui/ValueMonitorDialog.cpp
    gui/WatchWindow.cpp
    gui/AobInjectionDialog.cpp
    ${CMAKE_SOURCE_DIR}/include/gui/MainWindow.h
    ${CMAKE_SOURCE_DIR}/include/gui/ProcessListModel.h
    ${CMAKE_SOURCE_DIR}/include/gui/ProcessDialog.h
    ${CMAKE_SOURCE_DIR}/include/gui/PointerScannerDialog.h
    ${CMAKE_SOURCE_DIR}/include/gui/AutoAssemblerDialog.h
    ${CMAKE_SOURCE_DIR}/include/gui/MemoryViewerWindow.h
    ${CMAKE_SOURCE_DIR}/include/gui/ValueMonitorDialog.h
    ${CMAKE_SOURCE_DIR}/include/gui/WatchWindow.h
    ${CMAKE_SOURCE_DIR}/include/gui/AobInjectionDialog.h
    core/ProcessEnumerator.cpp
    core/TargetProcess.cpp
    core/MemoryScanner.cpp
    core/CodeInjector.cpp
    core/DebugWatch.cpp
)

add_executable(comfyengine ${SRC})

target_include_directories(comfyengine PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

find_library(CAPSTONE_LIB capstone)
if(NOT CAPSTONE_LIB)
    message(FATAL_ERROR "capstone library not found. Please install capstone (e.g. libcapstone-dev).")
endif()

target_link_libraries(comfyengine PRIVATE Qt6::Widgets ${CAPSTONE_LIB})

target_compile_definitions(comfyengine PRIVATE _GNU_SOURCE)
