
find_library (PAM_LIB NAMES libpam.so)
find_library (LDAP_LIB NAMES libldap.so)

add_library (pam_email_extractor SHARED pam_email_extractor.c)
target_include_directories (pam_email_extractor PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(pam_email_extractor "${PAM_LIB}" "${LDAP_LIB}")
SET_TARGET_PROPERTIES(pam_email_extractor PROPERTIES PREFIX "")



SET(CMAKE_C_FLAGS_TEST "${CMAKE_C_FLAGS_DEBUG} -DPAM_EMAIL_DEBUG=1")

if(CMAKE_BUILD_TYPE STREQUAL "Test")
  message("build debug executable")
  add_executable(pam_email_extractor_test pam_email_extractor_test.c)
  target_link_libraries(pam_email_extractor_test pam_email_extractor)
endif()
