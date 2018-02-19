#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "pam_email.h"


int main(int argc, char *argv[]){
  if (argc<4){
    fprintf(stderr, "Usage: %s <username> <email extractor> <param>\n", argv[0]);
    fprintf(stderr, " Extractors: ldap, gecos, git, default\n");
    return 1;
  }
  struct pam_email_ret_t test_ret = {0,0};
  if (strcmp(argv[2], "ldap")==0){
#ifndef NO_LDAP
    extract_ldap(&test_ret, argv[1], argv[3]);
#else
    fprintf(stderr, "Build without ldap support\n");
    return 1;
#endif
  } else if (strcmp(argv[2], "gecos")==0){
    extract_gecos(&test_ret, argv[1], argv[3]);
  } else if (strcmp(argv[2], "git")==0){
    extract_git(&test_ret, argv[1], argv[3]);
  } else if (strcmp(argv[2], "default")==0){
    extract_default(&test_ret, argv[1], argv[3]);
  } else {
    fprintf(stderr, "Extractor not found\n");
    return 1;
  }
  printf("Result:\n Email: %s\n Status returned: %i\n", test_ret.email, test_ret.state);
  free(test_ret.email);
  return 0;
}
