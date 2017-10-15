#include "pam_email.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>



struct pam_email_ret_t {
    int error;
    char *email;
    //char *prefix;
};


void extract_ldap(struct pam_email_ret_t *ret, const char *username, const char *param){
    ;
}

void extract_gecos(struct pam_email_ret_t *ret, const char *username, const char *param){
    ;
}

void extract_git(struct pam_email_ret_t *ret, const char *username, const char *param){
    char *fname = 0;
    while ()calloc(strlen(username)+16+1, sizeof(char));
    
    FILE *f = fopen(fname, "r");
}


void extract_default(struct pam_email_ret_t *ret, const char *username, const char *param){
    if (param){
        ret->email = calloc(strlen(username)+strlen(param)+1, sizeof(char));
        strncpy(ret->email, username, strlen(username));
        strncat(ret->email, param, strlen(param));
    } else {
        char hostname[256];
        if(!gethostname(hostname, 255))
            return;
        hostname[255] = '\0';
        ret->email = calloc(strlen(username)+strlen(hostname)+1, sizeof(char));
        strncpy(ret->email, username, strlen(username));
        strncat(ret->email, hostname, strlen(hostname));
    }
}




struct pam_email_ret_t extract_email(pam_handle_t *pamh, int argc, const char **argv){
    char use_all = 0;
    struct pam_email_ret_t email_ret;
    const char *param=0;
    char *extractor=0;
    const char *username;
    
    email_ret.email = 0;
    email_ret.error = 0;
    if (pam_get_item(pamh, PAM_USER, (const void**)&username)!=PAM_SUCCESS){
        email_ret.error = 1;
        goto error;
    }
    
    
    if(argc==1){
        use_all=1;
    }
    for (int countarg=1; countarg < argc || use_all!=0; countarg++){
        if (argc>1){
            param = strchr(argv[countarg], '=');
            if (param){
                if (param-argv[countarg] == 0){
                    email_ret.error = 1;
                    goto error;
                }
                // handle out of memory gracefully, elsewise login or whatever fails
                while(extractor==0){
                    // length +1 for \0
                    extractor = (char*)calloc(param-argv[countarg]+1, sizeof(char));
                }
                // copy without =, \0 is set by calloc
                strncpy(extractor, argv[countarg], param-argv[countarg]);
                // remove =
                param = param+1;
                // if strlea
            } else {
                // extractor is not freed in this case, so remove const
                extractor = (char *)argv[countarg];
            }
        }
        
        if ((use_all || strcmp(extractor, "ldap")==0) && (email_ret.email == 0 && email_ret.error == 0)){
            extract_ldap(&email_ret, username, param);
        }
        if ((use_all || strcmp(extractor, "gecos")==0) && (email_ret.email == 0 && email_ret.error == 0)){
            extract_gecos(&email_ret, username, param);
        }
        if ((use_all || strcmp(extractor, "git")==0) && (email_ret.email == 0 && email_ret.error == 0)){
            extract_git(&email_ret, username, param);
        }


        // last extractor, failback
        if ((use_all || strcmp(extractor, "default")==0) && (email_ret.email == 0 && email_ret.error == 0)){
            extract_default(&email_ret, username, param);
        }

        // cleanup
        if (param){
            free(extractor);
        }
        // param must be 0 elsewise extractor is incorrectly freed when not copied
        param = 0;
        extractor = 0;
        use_all = 0;
        if (email_ret.error != 0)
            goto error;
    }
    
    return email_ret;
error:
    if (email_ret.email)
        free(email_ret.email);
    if (param){
        free(extractor);
    }
    email_ret.email=0;
    return email_ret;
}


int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                               int argc, const char **argv){
    struct pam_email_ret_t ret = extract_email(pamh, argc, argv);
    if (ret.email){
        size_t lenemail = strlen(ret.email);
        // +1 char for \0
        char *emailtemp = (char*)calloc(strlen(PAM_EMAIL)+lenemail+1, sizeof(char));
        strncpy(emailtemp, PAM_EMAIL, strlen(PAM_EMAIL));
        strncat(emailtemp, ret.email, lenemail);
        pam_putenv(pamh, emailtemp);
        free(ret.email);
    }
    if (ret.error)
        return  PAM_CONV_ERR;
    else
        return PAM_IGNORE;
}
int pam_sm_open_session(pam_handle_t *pamh, int flags,
                               int argc, const char **argv){
    struct pam_email_ret_t ret = extract_email(pamh, argc, argv);
    if (ret.email){
        size_t lenemail = strlen(ret.email);
        // +1 char for \0
        char *emailtemp = (char*)calloc(strlen(PAM_EMAIL)+lenemail+1, sizeof(char));
        strncpy(emailtemp, PAM_EMAIL, strlen(PAM_EMAIL));
        strncat(emailtemp, ret.email, lenemail);
        pam_putenv(pamh, emailtemp);
        free(ret.email);
    }
    if (ret.error)
        return  PAM_CONV_ERR;
    else
        return PAM_IGNORE;
}
