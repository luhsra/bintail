macro (mvexe target)
    target_link_libraries(${target} ${MULTIVERSE_LIBRARIES})
    target_include_directories(${target} PRIVATE ${MULTIVERSE_INCLUDE_DIRS})
    target_compile_options(${target} PRIVATE ${MULTIVERSE_CFLAGS_OTHER})
endmacro (mvexe)

add_executable(mvcommit mvcommit.c)
mvexe(mvcommit)

add_executable(bss-nolib bss-nolib.c)
mvexe(bss-nolib)

add_executable(no-lib no-lib.c)
mvexe(no-lib)

add_executable(simple simple.c)
mvexe(simple)

add_test(NAME display_commit COMMAND $<TARGET_FILE:bintail-cli> -d mvcommit)
add_test(NAME display_bss    COMMAND $<TARGET_FILE:bintail-cli> -d bss-nolib)
add_test(NAME display_nolib  COMMAND $<TARGET_FILE:bintail-cli> -d no-lib)
add_test(NAME display_simple COMMAND $<TARGET_FILE:bintail-cli> -d simple)
