#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "pam_email_extractor.h"


int main(int argc, char *argv[]){
    const char *param=0;
    struct pam_email_ret_t email_ret;
    if (argc<2){
        fprintf(stderr, "Usage: %s <username> <email extractor=param...>\n", argv[0]);
        fprintf(stderr, " Extractors: ldap, gecos, file, git, default\n");
        return 1;
    }
    extract_email(&email_ret, argv[1], argc-2, (const char**) &argv[2]);
    printf("Result:\n Email: %s\n Status returned: %i\n", email_ret.email, email_ret.state);

    if (email_ret.email){
        size_t lenemail = strlen(email_ret.email);
        // +1 char for \0
        char *emailtemp = 0;
        // handle out of memory errors.Try multiple times until giving up
        for (size_t errcount=0; !emailtemp; errcount++){
            emailtemp = (char*)realloc(email_ret.email, (strlen(PAM_EMAIL)+lenemail+1)*sizeof(char));
#ifdef PAM_EMAIL_ALLOC_ERROR_MAX
            if (errcount>PAM_EMAIL_ALLOC_ERROR_MAX){
                free(email_ret.email);
                return PAM_BUF_ERR;
            }
#endif
        }
        // copy \0 terminator
        memmove(emailtemp+strlen(PAM_EMAIL), emailtemp, lenemail+1);
        memmove(emailtemp, PAM_EMAIL, strlen(PAM_EMAIL));
        printf(" PAM: %s\n", emailtemp);
        //pam_putenv(pamh, emailtemp);
        free(emailtemp);
    }
    return 0;
}
