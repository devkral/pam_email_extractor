

find_library (LIB_PAM NAMES libpam)
find_library (LIB_PAM_MISC NAMES libpam_misc)
find_library (LIB_PAM_C NAMES libpamc)

add_library (pam_email SHARED pam_email.c)
target_include_directories (pam_email PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(pam_email LIB_PAM LIB_PAM_MISC LIB_PAM_C)
