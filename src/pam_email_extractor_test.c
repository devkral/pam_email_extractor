#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "pam_email_extractor.h"


int main(int argc, char *argv[]){
    const char *param=0;
    struct pam_email_ret_t test_ret;
    if (argc<2){
        fprintf(stderr, "Usage: %s <username> <email extractor=param...>\n", argv[0]);
        fprintf(stderr, " Extractors: ldap, gecos, file, git, default\n");
        return 1;
    }
    extract_email(&test_ret, argv[1], argc-2, (const char**) &argv[2]);
    printf("Result:\n Email: %s\n Status returned: %i\n", test_ret.email, test_ret.state);
    if(test_ret.email)
        free(test_ret.email);
    return 0;
}
