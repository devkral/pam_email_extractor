
# does not work, but not required?
#find_library (LIB_PAM_LIBRARY NAMES libpam)
#find_library (LIB_LDAP_LIBRARY NAMES libldap)
# ${LIB_PAM_LIBRARY} ${LIB_LDAP_LIBRARY}

add_library (pam_email SHARED pam_email.c)
target_include_directories (pam_email PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(pam_email)
