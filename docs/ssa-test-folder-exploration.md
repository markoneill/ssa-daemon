
# Purpose
This document is an exploration into the different tests found in the `test_files` folder found in the ssa-daemon and the ssa kernel. This is WIP, and any further clarification/insights into the test folders are welcome. If anything is wrong in this document, change it to be correct.

## Notes
Any time `client auth` or `client authentication` is mentioned or used in the SSA, it is because it is part of a project to do client authentication using the SSA. As of June 2019, the paper for client authentication was not published and the details are only found in Mark O'Neils PhD Dissertation. A short summary of client authentication. 

Instead of using passwords to authenticate people to the web, many people are turning to stronger cryptography to authenticate users. In the Web world, WebAuthn has been standardized and will begin to be used. However, there are other methods. For example, other devices (such as phones) can be used to authenticate people. This would be more secure and an alternative to passwords. To implement client authentication, the SSA can be used to communicate with a phone that is connected to the WIFI. When a server wants to authenticate a client/user, the SSA will send a notification for authentication, and the phone would be used to autheneticate the person securely using cryptography. 

For more details, look for the paper (when it's published) or Mark O'Neil's Dissertation, Chapter 4.

## Tests

### Organization and Purpose of Tests

#### SSA Daemon

1. android_io - implements Android authentication for Securely, the App created to make the Client Authentication. In other words, this handles the Android half of client authentication.
2. cert_gen - doesn't actually test anything, just creates certs to be used for other testing
3. client_auth_client - client that can handle simple client authentication. Used for testing client authentication from the client side. Automatically connects to openrebellion.com (I don't think that website asks for client authentication, it is just an https website.)
4. https_client - has basic client and a threaded client
    - basic client - uses SSA, creates basic connection to www.google.com, does not have much info on what happened/errors
    - threaded_https_client - this appears to test the speed of the SSA, to test whether the SSA is much faster or slower than regular SSL calls. The SSA paper shows that the SSA is just as fast, and I bet they made their graph from this code.
        - uses SSA, creates connection to client using multiple threads; has options of running ssa vs regular ssl; 
        - there is a verbose setting, but it doesn't say too much, we could add more to it if desired
    - graph.py - small script to make a graph to from results; I'm guessing to show how the SSA performs compared to regular SSL calls
5. https_server - uses the SSA to create a basic server that reads the request from the client and sends the same request back to the client.
6. openssl_mod_tests - I don't know what these tests do. They don't interact with the SSA, and they won't even compile. I the following error
    ```
    [pbstrein@ilab3 openssl_mod_tests]$ make
    gcc client.o -o client -L../../openssl/lib -lcrypto -lssl
    /usr/bin/ld: client.o: in function `openssl_connect_to_host':
    client.c:(.text+0x1fd): undefined reference to `SSL_force_post_handshake_auth'
    /usr/bin/ld: client.o: in function `client_cert_callback':
    client.c:(.text+0x811): undefined reference to `SSL_set_client_auth_cb'
    collect2: error: ld returned 1 exit status
    make: *** [Makefile:14: client] Error 1
    ```
7. session_test - uses Open_SSL (not the SSA); tests resuming a session after connecting once
8. simple_test - has two servers, https_client.c and epoll_client.c
    - https_client.c - uses SSA to connect to host; host is given as a cmd line argument
    - epoll_client.c - uses SSA; expectes 1 cmd line argument which is the number of connections you want to make; default connects to www.phonixteam.net; uses epoll; to use this, modifications need to be made to line 242 and the make file needs to be changed
9. webserver-event - this appears to be the server they use to test client authentication. See the note above about client auth.
10. webserver-eventSSL - appears to be the same server as the webserver-event, but uses SSL instead of the SSA. 

I also noticed some scripts that may be used for testing. They build the right dependencies and make sure that everything gets made right. 

1. build-client-auth.sh - gets all the packages and files ready to run the client authentication piece of the SSA. 
2. install_packages.sh - installs necessary packages to run the SSA-daemon on fedora and ubuntu
3. removeClientAuth.sh - turns off all the servers and resets the computer after running all the things to do usability testing with client authentication. Kills the testShopServer, sslsplit, and the SSA-daemon, and turns the firewall back on after was shut off after running the sslsplit stuff. 
4. startClientAuth.sh - from the script. 
```
This script will build and run the programs necisery to
use Client Auth with Securly at the paymore.com domain.
If a Client Auth server is curently running remotly you
may specify the servers IP in the TESTSHOP_SERVER_IP
environment verialble to route paymore.com to that server
otherwise localhost will be used and a server will run
on your machine.
```




#### SSA Kernel

May 15th, 2019 - the tests are in one folder. When I try using make, it fails. I think it's because the fails are named wrong. I will change the files to get the tests to run and then see if I can summarize what the tests already do. 

1. tests.c - has the benchmarking tests for the socket command, connect, listen, and bind along with the baseline commands using SSL;
    - TODO: this test should have a usage script so it is easier to use and know how to use it besides looking through the code
2. time_parse.py - compares the baseline and benchmarking tests; runs the tests.c file and compares the output from the baseline to the benchmarking; requires keyword arguements of "socket", "bind", "listen", and "data". 
3. passfd_client.c - I'm not sure what this does, I think it tests that a connection fails when it has the wrong cert. But I'ts hard to tell because it isn't working for me right now.

### Other things found in the Repos

#### SSA-Daemon

##### Extras

There is also a folder with extras. These seem to have addon's to the SSA, like golang compatibility and other things. 

1. addons.c - appears to be some extra things added to the SSA. I'm not sure what it is trying to accomplihs
2. dynamicSSA - appears to be a library to dynamically upgrade sockets to use the SSA when previously using SSL; looks for network connections to happen using SSL_write, and upgrades it before writing/reading/whatever it does
3. golang - contains a diff/git patch that adds SSA to golang
4. openssl - has git patches to changing openssl to use authentication patches. Has 3 patches, it looks like they were built up to include more features than the previous patch.
5. sslsplit - from the sslsplit README.md - "This is a sslsplit patch that use the SSA for the intercepted connections."

##### QRDisplay

There is a folder with qrdisplay stuff. It had images and a program that can be run that asks to scan the qr image with your phone. It must be for client authentication, but I'm not sure how it relates.
