#include "pam_email_extractor.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pwd.h>

#ifndef NO_LDAP
#include <ldap.h>

// uri, base, (ldap attr, (filter, (sasl auth method)))
void extract_ldap(struct pam_email_ret_t *ret, const char *username, const char *param){
    char* parameters[5]={0,0,0,0,0};
    const int amount_parameters=5;
    unsigned char needs_unbind=0;
    const char *sep, *last;
    int err;
    char *filter=0, *tmp_filter, *tmp_filter_next, *email_attribute;
    char *ldap_attr[2]={0,0};
    size_t count_replacements=0;
    const size_t len_username = strlen(username);
    unsigned int ldap_version = LDAP_VERSION3;
    BerValue ** email_values;
    LDAP *ld_h=0;
    LDAPMessage *msg=0, *entry=0;
    last=param;
    for(int c=0; c<amount_parameters; c++){
        if (last)
            sep=strchr(last, ';');
        if (sep==0){
            switch (c){
                default:
                    ret->state = PAM_AUTH_ERR;
                    goto cleanup_ldap;
                    break;
                case 1:
                    while(!parameters[1])
                        parameters[1] = strdup(last);
                    while(!parameters[2])
                        parameters[2] = strdup("email");
                    while(!parameters[3])
                        parameters[3] = strdup("(uid=?)");
                    break;
                case 2:
                    while(!parameters[2])
                        parameters[2] = strdup(last);
                    while(!parameters[3])
                        parameters[3] = strdup("(uid=?)");
                    break;
                case 3:
                case 4:
                    while(!parameters[c])
                        parameters[c] = strdup(last);
                    break;
            }
            break;
        } else {
            if (sep!=last+1){
                while(!parameters[c])
                    parameters[c] = strndup(last, sep-last);
            }
            last=sep+1;
        }
    }
    // only extract email
    ldap_attr[0] = parameters[2];
    // create filter
    tmp_filter = strchr(parameters[3], '?');
    // count replacements
    while(tmp_filter)
    {
        count_replacements++;
        tmp_filter = strchr(tmp_filter+1, '?');
    }
    // create filter, shall never oom
    while (!filter){
        filter = (char*)calloc(len_username*count_replacements+strlen(parameters[3])+1, sizeof(char));
    }
    tmp_filter = parameters[3];
    tmp_filter_next = strchr(tmp_filter, '?');
    while(tmp_filter_next)
    {
        strncat(filter, tmp_filter, tmp_filter_next-tmp_filter);
        strncat(filter, username, strlen(username));
        tmp_filter = tmp_filter_next+1;
        tmp_filter_next = strchr(tmp_filter, '?');
    }
    strncat(filter, tmp_filter, strlen(tmp_filter));
#ifdef PAM_EMAIL_DEBUG_LDAP
    printf("Filter: \"%s\"\n", filter);
#endif
    if ((err=ldap_initialize(&ld_h, parameters[0])) != LDAP_SUCCESS){
        ret->state = PAM_AUTH_ERR;
        goto cleanup_ldap;
    }

    if ((err=ldap_set_option(ld_h, LDAP_OPT_PROTOCOL_VERSION, &ldap_version)) != LDAP_OPT_SUCCESS){
        ret->state = PAM_AUTH_ERR;
        goto cleanup_ldap;
    }
    if(parameters[4]){
        // TODO: rewrite parameters[4]: ,->spaces, use ldap_sasl_interactive_bind_s
        // TODO: last parameter should contain auth information

        if ((err=ldap_sasl_bind_s(ld_h, NULL, parameters[4], NULL, NULL, NULL, NULL)) != LDAP_SUCCESS ) {
            ret->state = PAM_AUTH_ERR;
            goto cleanup_ldap;
        }
        needs_unbind=1;
    }

    if ((err=ldap_search_ext_s(ld_h, parameters[1], LDAP_SCOPE_ONELEVEL, filter, ldap_attr, 0, NULL, NULL, NULL, 1, &msg)) != LDAP_SUCCESS) {
        ret->state = PAM_AUTH_ERR;
        goto cleanup_ldap;
    }

    entry = ldap_first_entry(ld_h, msg);
    if (entry){
        // there is only one attribute
        email_values = ldap_get_values_len(ld_h, entry, parameters[2]);
        // ensure there is only one value
        if(ldap_count_values_len(email_values)==1){
            while (!ret->email)
                ret->email=strdup(email_values[0]->bv_val);
        }
        ldap_value_free_len(email_values);
    }
    ldap_msgfree(msg);

cleanup_ldap:
    if(err!=LDAP_SUCCESS && err!=LDAP_OPT_SUCCESS)
        fprintf(stderr, "ldap error: %s\n", ldap_err2string(err));
    if(needs_unbind){
        ldap_unbind_ext_s(ld_h, NULL, NULL);
    }
    if(ld_h){
        ldap_destroy(ld_h);
    }
    if(filter)
        free(filter);
    for (int c=0; c<amount_parameters;c++){
        if (parameters[c]){
            free(parameters[c]);
        }
    }
}
#endif

void extract_gecos(struct pam_email_ret_t *ret, const char *username, const char *param){
    char *gecos_full=0, *emailfield=0;
    size_t email_length=0;
    struct passwd *pws = getpwnam (username);
    if (pws){
        while(!gecos_full)
            gecos_full = strdup(pws->pw_gecos);
        endpwent();
    }
    else {
        return;
    }

    // find email field
    emailfield = gecos_full;
    for(int c=0; c<3; c++){
        emailfield=strchr(emailfield, ',');
        if(!emailfield){
            free(gecos_full);
            return;
        }
        // next char after ,
        emailfield+=1;
    }
    // check if it is an email
    if(strchr(emailfield, '@')){
        while(isspace(emailfield[0]) && emailfield[0]!='\0')
            emailfield++;
        while(!isspace(emailfield[email_length]) && emailfield[email_length]!='\0')
            email_length++;
        while(!ret->email)
            ret->email = strndup(emailfield, email_length);
    }
    free(gecos_full);
}

void extract_file(struct pam_email_ret_t *ret, const char *username, char *param){
    char *fname=0, *home_name=0;
    char *line=NULL;
    char* email_begin=0;
    size_t file_name_length=0, email_length=0, home_length=0;
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
    if (!param){
        param = ".email";
    }
    file_name_length = strlen(param);
    // should not fail because of oom, 12 because of / and \0
    while (!fname){
        fname = calloc(home_length+file_name_length+1, sizeof(char));
    }
    strncpy(fname, home_name, home_length+1);
    // not needed anymore
    free(home_name);
    strncat(fname, param, file_name_length);
    FILE *emailfile = fopen(fname, "r");
    // not needed anymore
    free(fname);
    if (!emailfile)
        return;
    while(!feof(emailfile)){
        getline(&line, &line_length, emailfile);
        if(strchr(line, '@')){
            email_begin = line;
            while(isspace(email_begin[0]) && email_begin[0]!='\0')
                email_begin++;
            if (email_begin[0]=='\0')
                continue;
            while(!isspace(email_begin[email_length]) && email_begin[email_length]!='\0')
                email_length++;
            while(!ret->email)
                ret->email = strndup(email_begin, email_length);
            free(line);
            break;
        }
        free(line);
        line = NULL;
    }
    fclose(emailfile);
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
    FILE *gitfile = fopen(fname, "r");
    // not needed anymore
    free(fname);
    if (!gitfile)
        return;
    while(!feof(gitfile)){
        getline(&line, &line_length, gitfile);
        if(strstr(line, "email")){
            email_begin = strchr(line, '=');
            if (!email_begin)
                continue;
            // set here +1
            email_begin+=1;
            while(isspace(email_begin[0]) && email_begin[0]!='\0')
                email_begin++;
            if (email_begin[0]=='\0')
                continue;
            while(!isspace(email_begin[email_length]) && email_begin[email_length]!='\0')
                email_length++;
            while(!ret->email)
                ret->email = strndup(email_begin, email_length);
            free(line);
            break;
        }
        free(line);
        line = NULL;
    }
    fclose(gitfile);
}


void extract_default(struct pam_email_ret_t *ret, const char *username, const char *param){
    size_t len_username = strlen(username);
    if (param){
        // handle out of memory errors.Try multiple times until giving up
        for (size_t errcount=0; !ret->email; errcount++){
            ret->email = (char *)calloc(len_username+strlen(param)+2, sizeof(char));
#ifdef PAM_EMAIL_ALLOC_ERROR_MAX
            if (errcount>PAM_EMAIL_ALLOC_ERROR_MAX){
                ret->state=PAM_BUF_ERR;
                return;
            }
#endif
        }
        strncpy(ret->email, username, len_username+1);
        ret->email[len_username]='@';
        strncat(ret->email, param, strlen(param));
    } else {
        char hostname[256];
        if(!gethostname(hostname, 255))
            return;
        hostname[255] = '\0';
        // handle out of memory errors.Try multiple times until giving up
        for (size_t errcount=0; !ret->email; errcount++){
            ret->email = (char *)calloc(len_username+strlen(hostname)+2, sizeof(char));
#ifdef PAM_EMAIL_ALLOC_ERROR_MAX
            if (errcount>PAM_EMAIL_ALLOC_ERROR_MAX){
                ret->state=PAM_BUF_ERR;
                return;
            }
#endif
        }
        strncpy(ret->email, username, len_username+1);
        ret->email[len_username]='@';
        strncat(ret->email, hostname, strlen(hostname));
    }
}



// module name is NOT included in argv
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

    if(argc==0){
        argv = default_argv;
        argc = default_argc;
    }

    for (int countarg=0; countarg < argc; countarg++){
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
#ifdef PAM_EMAIL_ALLOC_ERROR_MAX
                if (errcount>PAM_EMAIL_ALLOC_ERROR_MAX){
                    email_ret.state=PAM_BUF_ERR;
                    goto error_extract_email;
                }
#endif
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
        if (strcmp(extractor, "file")==0 && (email_ret.email == 0 && email_ret.state == PAM_SUCCESS)){
            extract_file(&email_ret, username, param);
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
#ifdef PAM_EMAIL_ALLOC_ERROR_MAX
            if (errcount>PAM_EMAIL_ALLOC_ERROR_MAX)
                return PAM_IGNORE;
#endif
        }
        strncpy(emailtemp, PAM_EMAIL, strlen(PAM_EMAIL)+1);
        strncat(emailtemp, ret.email, lenemail);
        pam_putenv(pamh, emailtemp);
        free(ret.email);
    }
    if (ret.state!=PAM_SUCCESS && ret.state!=PAM_BUF_ERR)
        return PAM_AUTH_ERR;
    else
        return PAM_IGNORE;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags,
                   int argc, const char **argv){
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
#ifdef PAM_EMAIL_ALLOC_ERROR_MAX
            if (errcount>PAM_EMAIL_ALLOC_ERROR_MAX)
                return PAM_IGNORE;
#endif
        }
        strncpy(emailtemp, PAM_EMAIL, strlen(PAM_EMAIL)+1);
        strncat(emailtemp, ret.email, lenemail);
        pam_putenv(pamh, emailtemp);
        free(ret.email);
    }
    if (ret.state!=PAM_SUCCESS && ret.state!=PAM_BUF_ERR)
        return PAM_SESSION_ERR;
    else
        return PAM_IGNORE;
}
int pam_sm_close_session(pam_handle_t *pamh, int flags,
                         int argc, const char **argv){
    return PAM_IGNORE;
}
