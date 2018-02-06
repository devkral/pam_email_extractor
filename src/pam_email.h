#ifndef pam_email_h
#define pam_email_h

#define PAM_SM_AUTH 1
#define PAM_SM_SESSION 1
#include <security/pam_modules.h>


const char *PAM_EMAIL = "email=";
#define PAM_EMAIL_ALLOC_ERROR_MAX 3000

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv);
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv);
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv);
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv);


#endif
