cmake_minimum_required(VERSION 3.10)
project(bintail)

set( BINTAIL_SOURCES
    src/bintail.cpp
    src/main.cpp
    src/mvscn.cpp
    src/mvelem.cpp
)

add_executable(bintail ${BINTAIL_SOURCES})

set_target_properties(bintail PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
)

find_package(PkgConfig REQUIRED)
pkg_search_module(ELF REQUIRED libelf)

target_link_libraries(bintail ${ELF_LIBRARIES})
target_include_directories(bintail PUBLIC ${ELF_INCLUDE_DIRS})

