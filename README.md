# Simple email client 

Command line tool for sending emails. An implementation of SMTP in C, only supports sending via gmail at the moment. 

# Run (OS X)

    $ git clone https://github.com/connorwstein/email_client
    $ cd email_client
    $ gcc -lssl -lcrypto -lsasl2 -Wno-deprecated smtp_client.c -o client
    $ ./client

# Usage
    $ >>>> TO: mybuddy@gmail.com
    $ >>>> COMPOSE (~ to terminate): Whats up bud ~

	












