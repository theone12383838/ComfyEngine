cmake_minimum_required(VERSION 3.16)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 COMPONENTS Widgets REQUIRED)

add_executable(ce-mini-game main.cpp)
target_compile_features(ce-mini-game PRIVATE cxx_std_17)
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(ce-mini-game PRIVATE -O0 -g)
endif()

target_link_libraries(ce-mini-game PRIVATE Qt6::Widgets)
