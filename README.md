#Setup:

cd ./build
cmake ..
make
cp ./src/pam_email_extractor.so <dir for pam modules>

in pam service file add:
auth optional pam_email_extractor.so <configuration>
or
session optional pam_email_extractor.so <configuration>

#Naming
pam_email as well as pam_mail already existed.

#Configuration
items are position dependent and are seperated by whitespaces

possible items:
* gecos= : extract email from last gecos field
* git= : extract email from .gitconfig
* ldap=<url>;<dn>;<emailattribute>;<filter with ? replaced by username> : extract email from ldap. ? is replaced by username in filter query
* default=<default email domain> : default email domain to add to username; e.g. default=example.org and username is tom => tom@example.org. It is wise to use this at last position because it is a fallback

default without arguments:
gecos= git= default=localhost

## LDAP
LDAP is always available except if compiled with the NO_LDAPNO_LDAP flag

## default
Because in default the username is taken in whole I limit the amount of retries when allocating
