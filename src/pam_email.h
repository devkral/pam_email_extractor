#ifndef pam_email_h
#define pam_email_h
#include <security/pam_appl.h>


const char *PAM_EMAIL = "email=";

extern int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                               int argc, const char **argv);
extern int pam_sm_open_session(pam_handle_t *pamh, int flags,
                               int argc, const char **argv);

#endif