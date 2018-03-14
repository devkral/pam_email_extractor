# Setup

```sh
cd ./build
cmake ..
make
cp ./src/pam_email_extractor.so <dir for pam modules>
```

in pam service file add:
auth optional pam_email_extractor.so <configuration>
or
session optional pam_email_extractor.so <configuration>
(only of them is needed elsewise there could be duplicate ldap requests)

# Usage

In some program (here rpam2, ruby) retrieve the "email" pam environment variable:

```ruby
require 'rpam2'
# 'email' is the pam environment variable set by pam_email_extractor
Rpam2.getenv('<servicefile>', '<username>', '<password>', 'email')
# or easier
# returns hash with entry: 'email' -> email address
Rpam2.listenv('<servicefile>', '<username>', '<password>')
```

# Naming

pam_email as well as pam_mail already existed so I had to rename to pam_email_extractor.

# Configuration

items are position dependent and are seperated by whitespaces

possible items:
* gecos= : extract email from the gecos field of the user
* git= : extract email from user .gitconfig
* file=[.email] : extract email from user .email (or other file)
* ldap=&lt;url;dn;emailattribute;filter&gt; : extract email from ldap.
* default=[email-domain] : default email domain to add to username; e.g. default=example.org and username is tom => tom@example.org. Defaults to hostname

pam_email_extractor uses following aruments if no arguments were given:
file= gecos= git= default=

## ldap

LDAP is always available except if compiled with the NO_LDAP flag
ldap takes following ; seperated arguments:
* url: url to query, needs scheme e.g. ldaps://
* dn: domain of user objects
* emailattribute (default: "email"): name of emailattribute of user object
* filter (default: "(uid=?)"): filter query, ? is replaced by username in filter query

## default

Because in default the username is taken in whole I limit the amount of retries when allocating.
It should be used as a fallback and returns if not out of memory always an emailaddress. So it is wise to position it last.
If no hostname is given it uses system gethostname.
