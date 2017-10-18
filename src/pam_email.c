#include "pam_email.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>

#ifndef NO_LDAP
#include <ldap.h>
#endif


struct pam_email_ret_t {
    int error;
    char *email;
    //char *prefix;
};

#ifndef NO_LDAP
void extract_ldap(struct pam_email_ret_t *ret, const char *username, const char *param){
    char *parameters[5];
    char *sep, *next;
    char *filter=0;
    BerElement *ber;
    LDAP *ld_h;
    LDAPMessage *msg, *entry;
    next=param;
    for(int c=0; c<5; c++){
        if (next)
            sep=strchr(next, ';');
        if (sep==0){
            switch (c){
                case 0:
                    parameters[c] = strdup(param);
                    break;
                case 1:
                    parameters[c] = strdup("ou=users,dc=uaux,dc=de");
                    break;
                case 2:
                    parameters[c] = 0;
                    break;
                case 3:
                    parameters[c] = 0;
                    break;
            }
        } else {
            if (sep-next==0)
                parameters[c] = 0;
            else
                parameters[c] = strndup(next, sep-next);
            next=sep+1;
        }
    }
    while (!filter){
        // "(uid=)"
        filter = (char*)calloc(strlen(username)+6, sizeof(char));
    }
    strncpy(filter, "(uid=", 6);
    strncat(filter, username, strlen(username));
    strncat(filter, ")", 1);
    if (!(ld_h = ldap_init(parameter[0], LDAPS_PORT)))
        goto cleanup_ldap;
    if (ldap_set_option(ld_h, LDAP_OPT_PROTOCOL_VERSION, &LDAP_VERSION3) != LDAP_OPT_SUCCESS)
        goto cleanup_ldap;
    if (ldap_bind_s(ld_h, parameter[4], parameter[5], LDAP_AUTH_SIMPLE) != LDAP_SUCCESS ) {
        goto ldap_fallback;
    }
    goto ldap_ready;
ldap_fallback:
    ldap_destroy(ld);
    if (!(ld_h = ldap_init(parameter[0], LDAP_PORT)))
        goto cleanup_ldap;
    if (ldap_set_option(ld_h, LDAP_OPT_PROTOCOL_VERSION, &LDAP_VERSION3) != LDAP_OPT_SUCCESS)
        goto cleanup_ldap;
    if (ldap_bind_s(ld_h, parameter[4], parameter[5], LDAP_AUTH_SIMPLE) != LDAP_SUCCESS ) {
        goto cleanup_ldap_skip_unbind;
    }
ldap_ready:

    if (ldap_search_ext_s(ld_h, base, LDAP_SCOPE_ONELEVEL, filter, {"mail", 0}, 0, NULL, NULL, NULL, 1, &msg)!= LDAP_SUCCESS) {
        goto cleanup_ldap;
    }
    entry = ldap_first_entry(ld, msg);
    ret->email=strdup(ldap_first_attribute(ld, msg, &ber));
    ldap_msgfree(msg);

cleanup_ldap:
    ldap_unbind_s(ld);
cleanup_ldap_skip_unbind:
    ldap_destroy(ld);
    free(filter);
    for (int c=0; c<5;c++){
        if (parameters[c])
            free(c);
    }
}
#endif

void extract_gecos(struct pam_email_ret_t *ret, const char *username, const char *param){
    char *gecos=0, *emailfield=0;
    size_t email_length=0;
    struct passwd pws = *getpwnam (username);
    if (pws){
        gecos = strdup(pws->pw_gecos);
        emailfield = gecos;
        endpwent();
    }
    else {
        return;
    }
    for(int c=0; c<3;c++){
        emailfield=strchr(emailfield, ',')
        if(!emailfield){
            free(gecos);
            return;
        }
    }
    if(strchr(emailfield, '@')){
        while(isspace(emailfield[0]) && emailfield[0]!='\0')
            emailfield++;
        while(!isspace(emailfield[email_length]) && emailfield[0]!='\0')
            email_length++;
        ret->email = strndup(emailfield, email_length);
    }
    free(gecos);
}

void extract_git(struct pam_email_ret_t *ret, const char *username, const char *param){
    char *fname=0, *home_name=0;
    char *line=0;
    char* email_begin=0;
    size_t email_length=0, home_length=0;
    struct passwd *pws = getpwnam (username);
    if (pws){
        home_length = strlen(pws->pw_dir);
        home_name = strdup(pws->pw_dir);
        endpwent();
    }
    else {
        return;
    }
    // should not fail because of oom, 12 because of / and \0
    while (!fname){
        fname = calloc(home_length+12, sizeof(char));
    }
    strncpy(fname, home_name, home_length+1);
    // not needed anymore
    free(home_name);
    strncat(fname, "/.gitconfig", 11);
    FILE *f = fopen(fname, "r");
    // not needed anymore
    free(fname);
    if (!f)
        return;
    while(!feof(f)){
        getline(&line, &0, f);
        if(strstr(line, "email")){
            email_begin = strchr(line, '=');
            if (!email_begin)
                continue;
            while(isspace(email_begin[0]) && email_begin[0]!='\0')
                email_begin++;
            if (email_begin[0]=='\0')
                continue;
            while(!isspace(email_begin[email_length]) && email_begin[0]!='\0')
                email_length++;
            ret->email = strndup(email_begin, email_length);
            free(line);
            break;
        }
        free(line);
        line = NULL;
    }
    fclose(f);
}


void extract_default(struct pam_email_ret_t *ret, const char *username, const char *param){
    if (param){
        while (!ret->email){
            ret->email = (char *)calloc(strlen(username)+strlen(param)+1, sizeof(char));
        }
        strncpy(ret->email, username, strlen(username)+1);
        strncat(ret->email, param, strlen(param));
    } else {
        char hostname[256];
        if(!gethostname(hostname, 255))
            return;
        hostname[255] = '\0';
        while (!ret->email){
            ret->email = (char *)calloc(strlen(username)+strlen(hostname)+1, sizeof(char));
        }
        strncpy(ret->email, username, strlen(username)+1);
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
        goto error_extract_email;
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
                    goto error_extract_email;
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

#ifndef NO_LDAP
        if ((strcmp(extractor, "ldap")==0) && (email_ret.email == 0 && email_ret.error == 0)){
            if (param)
                extract_ldap(&email_ret, username, param);
            else {
                fprintf(stderr, "LDAP needs configuration");
            }
        }
#else
        if (strcmp(extractor, "ldap")==0){
            fprintf(stderr, "LDAP is not available");
        }
#endif
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
            goto error_extract_email;
    }

    return email_ret;
error_extract_email:
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
        char *emailtemp = 0;
        while (!emailtemp){
            emailtemp = (char*)calloc(strlen(PAM_EMAIL)+lenemail+1, sizeof(char));
        }
        strncpy(emailtemp, PAM_EMAIL, strlen(PAM_EMAIL)+1);
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
        char *emailtemp = 0;
        while (!emailtemp){
            emailtemp = (char*)calloc(strlen(PAM_EMAIL)+lenemail+1, sizeof(char));
        }
        strncpy(emailtemp, PAM_EMAIL, strlen(PAM_EMAIL)+1);
        strncat(emailtemp, ret.email, lenemail);
        pam_putenv(pamh, emailtemp);
        free(ret.email);
    }
    if (ret.error)
        return  PAM_CONV_ERR;
    else
        return PAM_IGNORE;
}
