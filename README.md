#How to use:
cd ./build
cmake ..
make
cp ./src/pam_email.so <dir for pam modules>

in pam service file add:
auth optional pam_email.so <configuration
or
session optional pam_email.so <configuration

#Naming
please don't confuse it with pam_mail.

#Configuration

