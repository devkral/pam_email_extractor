
find_library (PAM_LIB NAMES libpam.so)
find_library (LDAP_LIB NAMES libldap.so)

add_library (pam_email SHARED pam_email.c)
target_include_directories (pam_email PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(pam_email "${PAM_LIB}" "${LDAP_LIB}")
SET_TARGET_PROPERTIES(pam_email PROPERTIES PREFIX "")
