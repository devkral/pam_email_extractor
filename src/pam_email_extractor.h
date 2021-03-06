#ifndef pam_email_h
#define pam_email_h

#define PAM_SM_AUTH 1
#define PAM_SM_SESSION 1
#include <security/pam_modules.h>

#ifndef NO_PAM_EMAIL_ALLOC_ERROR_MAX
#ifndef PAM_EMAIL_ALLOC_ERROR_MAX
#define PAM_EMAIL_ALLOC_ERROR_MAX 3000
#endif
#endif

#ifndef PAM_EMAIL_VAR
#define PAM_EMAIL_VAR "email="
#endif

// 1. argument is not library path
const int default_argc = 4;
const char* default_argv[] = {"file", "gecos", "git", "default"};

const char *PAM_EMAIL = PAM_EMAIL_VAR;

struct pam_email_ret_t {
    int state;
    char *email;
    //char *prefix;
};

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv);
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv);
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv);
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv);

#ifdef PAM_EMAIL_DEBUG
void extract_email(struct pam_email_ret_t *email_ret,
const char *username, int argc, const char **argv);

#endif

#endif
