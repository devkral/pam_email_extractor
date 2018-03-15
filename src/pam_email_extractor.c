#include "pam_email_extractor.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pwd.h>

#ifndef NO_LDAP
#include <ldap.h>
//#include <sasl.h>

int pam_sasl_interact(LDAP *ld, unsigned flags, void *defaults, void *in)
{
    /**
    char *saslconfigstr=(char*)defaults;

    sasl_interact_t *interact = (sasl_interact_t*)in;
    if( ld == NULL )
        return LDAP_PARAM_ERROR;

    while( interact->id != SASL_CB_LIST_END ) {

        // default result
        char *dflt = (char*)interact->defresult;

        // TODO: extract from string elements, needs helper
        // see https://docs.oracle.com/cd/E86824_01/html/E54774/ldap-sasl-interactive-bind-s-3ldap.html for documentation
        // https://github.com/goeb/reference/blob/master/C/ldap_sasl_interactive_bind_s.c
        //dflt=NULL;
        // check if dflt is zero or ""
        interact->result = (dflt && *dflt) ? dflt : (char*)"";
        interact->len = strlen( (char*)interact->result );
        interact++;
    }*/
    return LDAP_SUCCESS;
}


//FIXME:  (sasl auth method) doesn't work
// uri, base, (ldap attr, (filter, (sasl auth method)))
void extract_ldap(struct pam_email_ret_t *ret, const char *username, const char *param){
    char* parameters[6]={0,0,0,0,0,0};
    const int amount_parameters=6;
    unsigned char needs_unbind=0;
    const char *sep, *last;
    int err;
    char *filter=0, *tmp_filter, *tmp_filter_next, *email_attribute;
    char *ldap_attr[2]={0,0};
    size_t count_replacements=0;
    const size_t len_username = strlen(username);
    unsigned int ldap_version = LDAP_VERSION3;
    unsigned int sasl_flags = LDAP_SASL_QUIET;
    BerValue ** email_values;
    LDAP *ld_h=0;
    LDAPMessage *msg=0, *entry=0;
    if (!param){
        fprintf(stderr, "LDAP needs configuration");
        return;
    }
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
                case 4:
                    // initialize sasl configstring with ""
                    while(!parameters[5])
                        parameters[5] = strdup("");
                case 3:
                case 5:
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
        char *replace_space;
        // rewrite , to spaces because spaces are not possible to input
        while ((replace_space=strchr(parameters[4], ','))) {
            replace_space[0] = ' ';
        }
        // TODO: last parameter should contain auth information

        if ((err=ldap_sasl_interactive_bind_s(ld_h, NULL, parameters[4], NULL, NULL, sasl_flags, pam_sasl_interact, &parameters[5])) != LDAP_SUCCESS ) {
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

void extract_file(struct pam_email_ret_t *ret, const char *username, const char *param){
    char *fname=0, *home_name=0;
    char *line=NULL;
    char* email_begin=0;
    size_t sub_path_length=0, email_length=0, home_length=0, line_length=0;
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
        param = "/.email";
    }
    sub_path_length = strlen(param);
    // should not fail because of oom, +1 for \0
    while (!fname){
        fname = calloc(home_length+sub_path_length+1, sizeof(char));
    }
    // not +1 because of calloc
    strncpy(fname, home_name, home_length);
    // not needed anymore
    free(home_name);
    // not +1 because of calloc
    strncat(fname, param, sub_path_length);
    FILE *emailfile = fopen(fname, "r");
    // not needed anymore
    free(fname);
    if (!emailfile)
        return;
    while(!feof(emailfile)){
        getline(&line, &line_length, emailfile);
        if(line && (email_begin=strchr(line, '@'))){
            // stop if next char is space or if line begin
            while(!isspace(email_begin[-1]) && email_begin!=line){
                email_begin--;
                email_length++;
            }
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
    size_t email_length=0, home_length=0, sub_path_length=0;
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
        param = "/.gitconfig";
    }
    sub_path_length = strlen(param);
    // should not fail because of oom, +1 for \0
    while (!fname){
        fname = calloc(home_length+sub_path_length+1, sizeof(char));
    }
    // not +1 because of calloc
    strncpy(fname, home_name, home_length);
    // not needed anymore
    free(home_name);
    // not +1 because of calloc
    strncat(fname, param, sub_path_length);
    FILE *gitfile = fopen(fname, "r");
    // not needed anymore
    free(fname);
    if (!gitfile)
        return;
    while(!feof(gitfile)){
        getline(&line, &line_length, gitfile);
        if(line && strstr(line, "email")){
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
void extract_email(struct pam_email_ret_t *email_ret,
const char *username, int argc, const char **argv){
    size_t extractor_name_length=0;
    const char *param=0;
    const char *extractor=0;
    int shall_free=0;

    email_ret->email = 0;
    email_ret->state = PAM_SUCCESS;

    if(argc==0){
        argv = default_argv;
        argc = default_argc;
    }

    for (int countarg=0; countarg < argc; countarg++){
        extractor = argv[countarg];
        param = strchr(extractor, '=');
        if (param){
            // param is extractor+1 = length
            extractor_name_length = param-extractor;
            // remove =
            param = param+1;
            // set to zero if not specified
            if (param[0]=='\0'){
                param = 0;
            }
        } else {
            extractor = argv[countarg];
            extractor_name_length = strlen(extractor);
        }

#ifndef NO_LDAP
        // without config not usable
        if (strncmp(extractor, "ldap", extractor_name_length)==0 && (email_ret->email == 0 && email_ret->state == PAM_SUCCESS)){
            extract_ldap(email_ret, username, param);
        }
#else
        if (strncmp(extractor, "ldap", extractor_name_length)==0){
            fprintf(stderr, "LDAP is not available");
        }
#endif
        if (strncmp(extractor, "gecos", extractor_name_length)==0 && (email_ret->email == 0 && email_ret->state == PAM_SUCCESS)){
            extract_gecos(email_ret, username, param);
        }
        if (strncmp(extractor, "file", extractor_name_length)==0 && (email_ret->email == 0 && email_ret->state == PAM_SUCCESS)){
            extract_file(email_ret, username, param);
        }
        if (strncmp(extractor, "git", extractor_name_length)==0 && (email_ret->email == 0 && email_ret->state == PAM_SUCCESS)){
            extract_git(email_ret, username, param);
        }
        // last extractor, fallback
        if (strncmp(extractor, "default", extractor_name_length)==0 && (email_ret->email == 0 && email_ret->state == PAM_SUCCESS)){
            extract_default(email_ret, username, param);
        }

        if (email_ret->state != PAM_SUCCESS)
            goto error_extract_email;
    }
    // don't cleanup if success
    return;
error_extract_email:
    if (email_ret->email){
        free(email_ret->email);
        email_ret->email=0;
    }
    email_ret->email=0;
}

int pam_set_email(
pam_handle_t *pamh, const int argc, const char **argv){
    const char *username;
    struct pam_email_ret_t email_ret;
    if (pam_get_item(pamh, PAM_USER, (const void**)&username)!=PAM_SUCCESS){
        return PAM_AUTH_ERR;
    }
    extract_email(&email_ret, username, argc, argv);
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
        pam_putenv(pamh, emailtemp);
        // uses copy so free here
        free(emailtemp);
    }
    return email_ret.state;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                        int argc, const char **argv){
    int retstate = pam_set_email(pamh, argc, argv);
    if (retstate!=PAM_SUCCESS && retstate!=PAM_BUF_ERR)
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
    int retstate = pam_set_email(pamh, argc, argv);
    if (retstate!=PAM_SUCCESS && retstate!=PAM_BUF_ERR)
        return PAM_SESSION_ERR;
    else
        return PAM_IGNORE;
}
int pam_sm_close_session(pam_handle_t *pamh, int flags,
                         int argc, const char **argv){
    return PAM_IGNORE;
}
