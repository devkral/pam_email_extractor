#ifndef pam_email_h
#define pam_email_h

#define PAM_SM_AUTH 1
#define PAM_SM_SESSION 1
#include <security/pam_modules.h>

#ifndef PAM_EMAIL_ALLOC_ERROR_MAX
#define PAM_EMAIL_ALLOC_ERROR_MAX 3000
#endif

#ifndef PAM_EMAIL_VAR
#define PAM_EMAIL_VAR "email="
#endif

// 1. argument is not library path
const int default_argc = 3;
const char* default_argv[] = {"gecos=", "git=", "default=localhost"};

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
#ifndef NO_LDAP
void extract_ldap(struct pam_email_ret_t *ret, const char *username, const char *param);
#endif
void extract_gecos(struct pam_email_ret_t *ret, const char *username, const char *param);
void extract_git(struct pam_email_ret_t *ret, const char *username, const char *param);
void extract_default(struct pam_email_ret_t *ret, const char *username, const char *param);
#endif

#endif
