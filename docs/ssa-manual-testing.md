
May 24th, 2019
I started working on manual tests. I realized that the SSA is not doing certificate checking. When I run "normal", and I run the simple-test and give it expired.badssl.com, it still continued to connect to the site and gave no error. We will need to fix this. I will also need to figure out how to best verify that the test works/doesn't work.

- I tried installing Trustbase to see if I could get it to give an error, but got the following error
```
[pbstrein@ilab3 trustbase-linux]$ make
gcc -Wall -O3 -fpic -g -c policy-engine/netlink.c -I/usr/include/libnl3 -I/usr/include/python2.7 -o policy-engine/netlink.o
policy-engine/netlink.c:4:10: fatal error: sqlite3.h: No such file or directory
 #include <sqlite3.h>
          ^~~~~~~~~~~
compilation terminated.
make: *** [Makefile:138: policy-engine/netlink.o] Error 1
```
Solution: Turns out the installer.sh wasn't installing the right packages for me because it couldn't find one of the packages. Turns out that if it cannot find one package, it will not install any of them. I need to figure out how to make it go thorugh each package independently. 
    - maybe add the --skip-broken flag to the command, not sure if it works
 

I got trustbase running, but it cannot do SSL certificates right. In fact, when I have it running, the internet in my browser fails because the checks do not work. I have to remove the module. If we want to get the whole thing working (with revocation), we are going to have to get trustbase working again. 



Tuesday, May 29th, 2019
I started working on the manual tests excluding certification revocation (I'm going to wait to talk to Dr. Zappala about it.) So I'm going to continue and run the tests manually.

To make the tests work right, we will need to create a simple server and a simple client that can do the tests. THe simple__test folder has a server that works right under most situations, except to test the different versions of TLS using badssl.com. We need to specify the port so that we can check TLS 1.0 and TLS 1.1.

**Question** What should be the expected behavior if we try to set the MinProtocol to be higher than something we connect? Should it fail or should it be able to connect? The paper and the config file are different (TLS VERSION in paper VS MinProtocol in config file)

##Administrator Control

### MinProtocol
1. Change MinProtocol to be "1.2" in the ssa.cfg and restart the SSA
    - run ```./https_client tls-v1-2.badssl.com 1012``` 
        - **Expected Behavior** 
            - the client receives an html response 
            - no logging errors should appear
    - run ```./https_client tls-v1-0.badssl.com 1010``` and you should get the following errors
        - **Expected Behavior**
            - from the client: ```connect: No route to host failed to find a suitable address for connection" from the client and receive a logging error ```
            - from the SSA: ```ERROR:   SSL error from bufferevent: ssl_choose_client_version [unsupported protocol]```
    - run ```./https_client tls-v1-1.badssl.com 1011``` 
        - **Expected Behavior** 
            - from the client: ```connect: No route to host failed to find a suitable address for connection" from the client and receive a logging error ```
            - from the SSA: ```ERROR:   SSL error from bufferevent: ssl_choose_client_version [unsupported protocol]```
2. Change MinProtocol to be "1.0" in the ssa.cfg
    - run ```./https_client tls-v1-2.badssl.com 1012``` 
        - **Expected Behavior** 
            - the client receives an html response 
            - no logging errors should appear
    - run ```./https_client tls-v1-0.badssl.com 1010```
        - **Expected Behavior**
            - from the client: ```connect: No route to host failed to find a suitable address for connection" from the client and receive a logging error ```
            - from the SSA: ```ERROR:   SSL error from bufferevent: ssl_choose_client_version [unsupported protocol]```
            
### MaxProtocol
2. Change MinProtocol to be "1.1" and add ```MaxProtocol: "1.1"``` in the ssa.cfg.
    - run ```./https_client tls-v1-1.badssl.com 1011``` 
        - **Expected Behavior** 
            - the client receives an html response 
            - no logging errors should appear
    - run ```./https_client tls-v1-0.badssl.com 1010```
        - **Expected Behavior**
            - from the client: ```connect: No route to host failed to find a suitable address for connection" from the client and receive a logging error ```
            - from the SSA: ```ERROR:   SSL error from bufferevent: ssl_choose_client_version [unsupported protocol]```
    - run ```./https_client tls-v1-2.badssl.com 1012```
        - **Expected Behavior**
            - from the client: ```connect: No route to host failed to find a suitable address for connection" from the client and receive a logging error ```
            - from the SSA: ```ERROR:   SSL error from bufferevent: ssl_choose_client_version [unsupported protocol]```
            
3. Change MinProtocol to be "1.2" and add ```MaxProtocol: "1.1"``` to the default profile in the ssa.cfg.
    - run the ssa daemon
        - **Expected Behavior**
            -- the ssa should fail to run and give an error stating that the MinProtocol was higher than the MaxProtocl
            
4. Change MinProtocol to be "1.2" in the default profile and add ```MaxProtocol: "1.1"``` to the ncat profile.
    - it should look like this 
    ```
    {
        Application: "/bin/ncat"
        MaxProtocol: "1.1"
        CipherSuite: "ECDH+AESGCM:DH+AESGCM:ECDH+AES256:!aNULL:!MD5:!DSS"
    }
   ```
    - run the ssa daemon
        - **Expected Behavior**
            -- the ssa should fail to run and give an error stating that the MinProtocol was higher than the MaxProtocol for the application you added it to
            
### CipherSuite 
5. Change CipherSuite to ```CipherSuite: "RSA:DH"```
    - run ```/https_client rsa4096.badssl.com 443```
        - **Expected Behavior**
            - from the client: get html content
            - from the SSA: no error logs
    - run ```./https_client dh2048.badssl.com 443```
        - **Expected Behavior**
            - from the client: get html content
            - from the SSA: no error logs
6. Change CipherSuite to ```CipherSuite: "RSA:!DH"```
    - run ```/https_client rsa4096.badssl.com 443```
        - **Expected Behavior**
            - from the client: get html content
            - from the SSA: no error logs
    - run ```./https_client dh2048.badssl.com 443```
        - **Expected Behavior**
            - from the client: get error output, similar to ```connect: No route to host failed to find a suitable address for connection```
            - from the SSA: should get some error log similar to ```ERROR:   SSL error from bufferevent: ssl3_read_bytes [sslv3 alert handshake failure]```
            
### TrustStoreLocation

#### Fedora
1. Change TrustStoreLocation to ```TrustStoreLocation: "/etc/pki/tls/certs/ca-bundle.crt"```
    - run ```/https_client tls-v1-2.badssl.com 1012```
        - **Expected Behavior**
            - from the client: get html content
            - from the SSA: no error logs, acccepted and handled connection
2. Change TrustStoreLocation to ```TrustStoreLocation: "/etc/pki/tls/certs/blah.crt"```
    - run ```/https_client tls-v1-2.badssl.com 1012```
        - **Expected Behavior**
            - from the client: get html content
            - from the SSA: no error logs, acccepted and handled connection
3. Remove TrustStoreLocation
    - run ```/https_client tls-v1-2.badssl.com 1012```
        - **Expected Behavior**
            - from the SSA: daemon crashes, get log like ```ERROR:   Default configuration for TrustStoreLocation not set.  ```


