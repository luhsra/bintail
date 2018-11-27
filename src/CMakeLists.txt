project(libbintail VERSION 0.1)

add_library(libbintail
    bintail.cpp
    mvscn.cpp
    mvelem.cpp
)

target_include_directories(libbintail PUBLIC
    include
    PRIVATE
    ${ELF_INCLUDE_DIRS} ${MULTIVERSE_INCLUDE_DIRS})
#remove elf because link?

set_target_properties(libbintail PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
)

target_link_libraries(libbintail ${ELF_LIBRARIES})

add_executable(testlib
    testlib.cpp)

set_target_properties(testlib PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
)

target_link_libraries(testlib
    libbintail)

install(TARGETS libbintail DESTINATION lib)

add_executable(bintail-cli
    main.cpp
)

set_target_properties(bintail-cli PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
)

target_link_libraries(bintail-cli
    libbintail)

install(TARGETS bintail-cli DESTINATION bin)
