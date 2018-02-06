#include "pam_email.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>

#ifndef NO_LDAP
#include <ldap.h>
const char* ldap_attrs[] = {"email", 0};
#endif

// +1 for adjustment
const int default_argc = 4;
const char* default_argv[] = {"gecos=", "git=", "default="};

struct pam_email_ret_t {
    int state;
    char *email;
    //char *prefix;
};

#ifndef NO_LDAP
// uri, base, (filter, (user, (pw)))
void extract_ldap(struct pam_email_ret_t *ret, const char *username, const char *param){
    char *parameters[5]={0,0,0,0,0};
    const char *sep, *next;
    char *filter=0, *tmp_filter, *tmp_filter2, *first_attribute;
    size_t count_replacements=0;
    unsigned int ldap_version = LDAP_VERSION3;
    BerElement *ber;
    LDAP *ld_h;
    LDAPMessage *msg, *entry;
    next=param;
    for(int c=0; c<=5; c++){
        if (next)
            sep=strchr(next, ';');
        if (sep==0){
            switch (c){
                default:
                    ret->state = PAM_AUTH_ERR;
                    goto cleanup_ldap_skip_unbind;
                    break;
                case 1:
                    while(!parameters[1])
                        parameters[1] = strdup(param);
                    parameters[2] = "(uid=?)";
                    parameters[3] = 0;
                    parameters[4] = 0;
                    break;
                case 2:
                    while(!parameters[2])
                        parameters[2] = strdup(param);
                    parameters[3] = 0;
                    parameters[4] = 0;
                    break;
                case 3:
                    while(!parameters[3])
                        parameters[3] = strdup(param);
                    parameters[4] = 0;
                    break;
                case 4:
                    while(!parameters[4])
                        parameters[4] = strdup(param);
                    break;
            }
            break;
        } else {
            if (sep-next==0){
                parameters[c] = 0;
            }
            else{
                while(!parameters[c])
                    parameters[c] = strndup(next, sep-next);
            }
            next=sep+1;
        }
    }
    tmp_filter = strchr(parameters[3], '?');
    while(*tmp_filter)
    {
        count_replacements++;
        tmp_filter = strchr(tmp_filter+1, '?');
    }
    while (!filter){
        filter = (char*)calloc(strlen(username)*count_replacements+strlen(parameters[3])+1, sizeof(char));
    }
    tmp_filter = parameters[3];
    tmp_filter2 = strchr(parameters[3], '?');
    if(tmp_filter2==0){
        ret->state = PAM_AUTH_ERR;
        goto cleanup_ldap_skip_unbind;
    }
    while(*tmp_filter2)
    {
        strncat(filter, tmp_filter, tmp_filter2-tmp_filter);
        strncat(filter, username, strlen(username));
        tmp_filter = tmp_filter2;
        tmp_filter2 = strchr(tmp_filter+1, '?');
    }
    strncat(filter, tmp_filter, strlen(tmp_filter));
    if (!ldap_initialize(&ld_h, parameters[0])){
        ret->state = PAM_AUTH_ERR;
        goto cleanup_ldap;
    }
    if (ldap_set_option(ld_h, LDAP_OPT_PROTOCOL_VERSION, &ldap_version) != LDAP_OPT_SUCCESS){
        ret->state = PAM_AUTH_ERR;
        goto cleanup_ldap;
    }
    /**
    if(parameter[4]){
        // TODO: prefi with u: ?
    }
    if(parameter[5]){

    }
    if (ldap_sasl_bind_s(ld_h, parameter[4], "", parameter[5], NULL, NULL) != LDAP_SUCCESS ) {
        ret->error = PAM_AUTH_ERR;
        goto cleanup_ldap;
    }*/
    if (ldap_sasl_bind_s(ld_h, NULL, "", NULL, NULL, NULL, NULL) != LDAP_SUCCESS ) {
        ret->state = PAM_AUTH_ERR;
        goto cleanup_ldap;
    }

    if (ldap_search_ext_s(ld_h, parameters[1], LDAP_SCOPE_ONELEVEL, filter, (char**)ldap_attrs, 0, NULL, NULL, NULL, 1, &msg)!= LDAP_SUCCESS) {
        goto cleanup_ldap;
    }
    entry = ldap_first_entry(ld_h, msg);
    first_attribute = ldap_first_attribute(ld_h, msg, &ber);
    while (!ret->email)
        ret->email=strdup(first_attribute);
    ldap_msgfree(msg);

cleanup_ldap:
    ldap_unbind_ext_s(ld_h, NULL, NULL);
cleanup_ldap_skip_unbind:
    ldap_destroy(ld_h);
    free(filter);
    for (int c=0; c<5;c++){
        if (parameters[c])
            free(parameters[c]);
    }
}
#endif

void extract_gecos(struct pam_email_ret_t *ret, const char *username, const char *param){
    char *gecos=0, *emailfield=0;
    size_t email_length=0;
    struct passwd *pws = getpwnam (username);
    if (pws){
        while(!gecos)
            gecos = strdup(pws->pw_gecos);
        emailfield = gecos;
        endpwent();
        free(pws);
    }
    else {
        return;
    }
    for(int c=0; c<3;c++){
        emailfield=strchr(emailfield, ',');
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
    char *line=NULL;
    size_t line_length=0;
    char* email_begin=0;
    size_t email_length=0, home_length=0;
    struct passwd *pws = getpwnam (username);
    if (pws){
        home_length = strlen(pws->pw_dir);
        while(!home_name)
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
        getline(&line, &line_length, f);
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
        // handle out of memory gracefully, elsewise login or whatever fails
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
        // handle out of memory gracefully, elsewise login or whatever fails
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
    email_ret.state = PAM_SUCCESS;
    if (pam_get_item(pamh, PAM_USER, (const void**)&username)!=PAM_SUCCESS){
        email_ret.state = PAM_AUTH_ERR;
        goto error_extract_email;
    }


    if(argc==1){
        argv = default_argv;
        argc = default_argc;
    }
    for (int countarg=1; countarg < argc; countarg++){
        if (argc>1){
            param = strchr(argv[countarg], '=');
            if (param){
                if (param-argv[countarg] == 0){
                    email_ret.state = PAM_AUTH_ERR;
                    goto error_extract_email;
                }
                // handle out of memory gracefully, elsewise login or whatever fails
                for (size_t errcount=0; !extractor; errcount++){
                    // length +1 for \0
                    extractor = (char*)calloc(param-argv[countarg]+1, sizeof(char));
                    if (errcount>PAM_EMAIL_ALLOC_ERROR_MAX){
                        email_ret.state=PAM_BUF_ERR;
                        goto error_extract_email;
                    }
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
        // without config not usable => no use_all auto activation
        if (strcmp(extractor, "ldap")==0 && (email_ret.email == 0 && email_ret.state == PAM_SUCCESS)){
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
        if (strcmp(extractor, "gecos")==0 && (email_ret.email == 0 && email_ret.state == PAM_SUCCESS)){
            extract_gecos(&email_ret, username, param);
        }
        if (strcmp(extractor, "git")==0 && (email_ret.email == 0 && email_ret.state == PAM_SUCCESS)){
            extract_git(&email_ret, username, param);
        }


        // last extractor, failback
        if (strcmp(extractor, "default")==0 && (email_ret.email == 0 && email_ret.state == PAM_SUCCESS)){
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
        if (email_ret.state != PAM_SUCCESS)
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
        // handle out of memory errors.Try multiple times until giving up
        for (size_t errcount=0; !emailtemp; errcount++){
            emailtemp = (char*)calloc(strlen(PAM_EMAIL)+lenemail+1, sizeof(char));
            if (errcount>PAM_EMAIL_ALLOC_ERROR_MAX)
                return PAM_BUF_ERR;
        }
        strncpy(emailtemp, PAM_EMAIL, strlen(PAM_EMAIL)+1);
        strncat(emailtemp, ret.email, lenemail);
        pam_putenv(pamh, emailtemp);
        free(ret.email);
    }
    if (ret.state!=PAM_SUCCESS)
        return ret.state;
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
        // handle out of memory errors.Try multiple times until giving up
        for (size_t errcount=0; !emailtemp; errcount++){
            emailtemp = (char*)calloc(strlen(PAM_EMAIL)+lenemail+1, sizeof(char));
            if (errcount>PAM_EMAIL_ALLOC_ERROR_MAX)
                return PAM_BUF_ERR;
        }
        strncpy(emailtemp, PAM_EMAIL, strlen(PAM_EMAIL)+1);
        strncat(emailtemp, ret.email, lenemail);
        pam_putenv(pamh, emailtemp);
        free(ret.email);
    }
    if (ret.state!=PAM_SUCCESS)
        return ret.state;
    else
        return PAM_IGNORE;
}
