
## Purpose
This README goes through all the steps to manually test the features of the SSA to make sure it has basic functionality. These tests cover both administrator options and developer options while using the SSA. 

This README is a WIP and can be changed and added to as needed. Any place where there is a TODO is further work that needs to be done to finish this documentation.

## Table of Contents
- [TODOS](#todos)
- [Administrator Options](#administrator-options)
    - [Min Protocol](#minprotocol)
    - [Max Protocol](#maxprotocol)
    - [CipherSuite](#ciphersuite)
    - [TrustStoreLocation](#truststorelocation)
    - [AppCustomValidation](#appcustomvalidation)
- [Client Testing](#client-testing)
    - [Basic Client Functionality](#basic-client-functionality)
    - [Client Socket Options](#client-socket-options)
- [Server Testing](#server-testing)
    - [Basic Server Functionality](#basic-server-functionality)
    - [Server Socket Options](#server-socket-options)


## TODOs
1. If the SSA gets a wrong path to the cert file during setsockopt with the option TLS_CERTIFICATE_CHAIN, it gets a segfault, not an error
2. How do we test client certificates? How do we know that they work/got set right?
3. When I use getsockopt with TLS_CERTIFICATE_CHAIN, I get a value of '', meaning empty. We need to check whether that is right or wrong and change it if it is wrong
4. Add tests/fix tests when certificate validation is fixed - see TrustStoreLocation

## Administrator Options
### MinProtocol
1. Change MinProtocal to be "1.2" in the ssa.cfg and run the SSA
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
2. Change MinProtocol to be "1.0" in the ssa.cfg and run SSA
    - run ```./https_client tls-v1-2.badssl.com 1012``` 
        - **Expected Behavior** 
            - the client receives an html response 
            - no logging errors should appear and a TLSv1.2 connection should be made
    - run ```./https_client tls-v1-0.badssl.com 1010```
        - **Expected Behavior**
            - from the client: ```connect: No route to host failed to find a suitable address for connection" from the client and receive a logging error ```
            - from the SSA: ```ERROR:   SSL error from bufferevent: ssl_choose_client_version [unsupported protocol]```
            
### MaxProtocol
1. Change MinProtocol to be "1.1" and add ```MaxProtocol: "1.1"``` and run SSA
    - run ```./https_client tls-v1-1.badssl.com 1011``` 
        - **Expected Behavior** 
            - the client receives an html response 
            - no logging errors should appear and a TLS 1.1 connection should be made
    - run ```./https_client tls-v1-2.badssl.com 1012``` 
        - **Expected Behavior** 
            - the client gets an error; similar to something like ```connect: No route to host
                                                                     failed to find a suitable address for connection```
            - logging should show that the connection ended, for example, I got ```DEBUG:   encrypted endpoint got EOF```
2. Change MinProtocl to be "1.2" and MaxProtocol to be "1.1" and run SSA
    - run ```./https_client tls-v1-2.badssl.com 1012``` 
        - **Expected Behavior** 
            - the SSA should exit and get an error similar to the following ```ERROR:   Default configuration for MinProtocol is greater than default configuration for MaxProtocol```
3. Change MinProtocl to be "1.2", remove MaxProtocol from the default profile, and add ```MaxProtocl: 1.1``` to the /bin/ncat profile and run SSA
    - run ```./https_client tls-v1-2.badssl.com 1012``` 
        - **Expected Behavior** 
            - the SSA will exit, and give an error stating that the MinProtocol is higher than the MaxProtocol
4. Change MinProtocl to be "1.1", change MaxProtocol to be ```MaxProtocol: "1.4"``` and run SSA
    - run ```./https_client tls-v1-2.badssl.com 1012``` 
        - **Expected Behavior** 
            - the SSA will exit; should give logging errors that it could not parse 1.4 and that the MinProtocol is higher than the MaxProtocol
        
### CipherSuite
3. Change MinProtocl to "1.2" for the rest of the tests. Set CipherSuite to ```CipherSuite: "RSA:DH"``` and run SSA
    - run ```/https_client rsa4096.badssl.com 443```
        - **Expected Behavior**
            - from the client: get html content
            - from the SSA: no error logs
    - run ```./https_client dh2048.badssl.com 443```
        - **Expected Behavior**
            - from the client: get html content
            - from the SSA: no error logs
4. Change CipherSuite to ```CipherSuite: "RSA:!DH"``` and run SSA
    - run ```/https_client rsa4096.badssl.com 443```
        - **Expected Behavior**
            - from the client: get html content
            - from the SSA: no error logs
    - run ```./https_client dh2048.badssl.com 443```
        - **Expected Behavior**
            - from the client: get error output, similar to ```connect: No route to host failed to find a suitable address for connection```
            - from the SSA: should get some error log similar to ```ERROR:   SSL error from bufferevent: ssl3_read_bytes [sslv3 alert handshake failure]```
            
### TrustStoreLocation 
**TODO: when these tests were made, certificate validation was not done. We need to get the defined behavior of these tests when certificate validation is added in**
1. set TrustSToreLocation to be ```TrustStoreLocation: "/etc/pki/tls/certs/ca-bundle.crt"``` on Fedora or ```TrustStoreLocation: "/etc/ssl/certs/ca-certificates.crt"``` on Ubuntu and run SSA
    - run ```/https_client tls-v1-2.badssl.com 1012```
        - **Expected Behavior**
            - from the client: get html content
            - from the SSA: no error logs
2. set TrustStoreLocation to be ```TrustStoreLocation : "/I/dont/exist/cert.crt``` and run SSA
    - run ```/https_client tls-v1-2.badssl.com 1012```
        - **Expected Behavior**
            - you should not get any content from the socket and the SSA should give some error logs stating that no certs were found
3. remove TrustSToreLocation and run SSA
    - **Expected Behavior**
        - the SSA should exit and say ```ERROR:   Default configuration for TrustStoreLocation not set. ```
    

### AppCustomValidation
**TODO: figure out how to test this and get the right results. Might need to talk to Dr. Zapala or Mark.

## Client Testing

### Basic Client Functionality
To test basic SSA functionality, go to the `test_files/manual_tests/` folder in the ssa-daemon and do the following:
1. Make sure the SSA is running
2. Run `make` to build the client (and the server)
3. Run `./https_client www.google.com 443`

**Expected Result**
You should create a secure connection to google. In order, you should see the following:
1. A peer certificate
2. A peer identity, sometime similar to `/C=US/ST=California/L=Mountain View/O=Google LLC/CN=www.google.com`
3. An HTTP 200 response

### Client Socket Options

#### Prerequisites 
Add the following lines of code to the https_client. I put them between lines 49 and 51.
```c
        int optname = TLS_SESSION_TTL;
        char* set_optval = "-1";
        socklen_t set_optlen = strlen(set_optval) + 1;
        if (setsockopt(sock_fd, IPPROTO_TLS, optname, set_optval, set_optlen) == -1) {
            perror("setsockopt: optname");
            close(sock_fd);
			continue;
		}
        printf("setsockopt: set opt '%d' -> '%s'\n", optname, set_optval);

        char get_optval[4096];
        socklen_t get_optlen = sizeof(get_optval);
        if (getsockopt(sock_fd, IPPROTO_TLS, optname, get_optval, &get_optlen) == -1) {
            perror("getsockopt: optname");
			close(sock_fd);
			continue;
		}
        printf("Used getsockopt: get_optval ='%s'\n", get_optval);

```

This will enable easier testing and of the different socket options.

#### TLS_REMOTE_HOSTNAME
**TODO: add tests and expected behavior**

#### TLS_HOSTNAME
**TODO: add tests and expected behavior**

#### TLS_CERTIFICATE_CHAIN and TLS_PRIVATE_KEY
1. Test getsockopt and TLS_PRIVATE_KEY
    1. set `optname` to `TLS_PRIVATE_KEY`
    2. set `set_optval` to `keys/key_a.pem`
    3. run `make`
    3. run `./https_client www.google.com 443`
    - **Expected Behavior** 
        - you should get an error `Protocol not available` when using getsockopt and `TLS_PRIVATE_KEY`
        
**TODO: figure out how to find correct client behavior with certs and private keys**
For the rest of the tests, you may need additional code to set a private key and the certificate chain. You may use the following code, and may place it right after the code above
```c
        int optname2 = TLS_PRIVATE_KEY;
        char* set_optval2 = "keys/key_a.pem";
        socklen_t set_optlen2 = strlen(set_optval2) + 1;
        if (setsockopt(sock_fd, IPPROTO_TLS, optname2, set_optval2, set_optlen2) == -1) {
            perror("setsockopt: optname2");
			close(sock_fd);
			continue;
		}
        printf("setsockopt: set opt '%d' -> '%s'\n", optname2, set_optval2);

```
1. Testing valid certificate and private key
    1. set `optname` to `TLS_CERTIFICATE_CHAIN`
    2. set `set_optval` to `keys/certificate_a.pem`
    3. set `optname2` to `TLS_PRIVATE_KEY`
    4. set `set_optval2` to `keys/key_.pem`
    5. run `make`
    6. run `./https_client www.google.com 443` **TODO: this may need to change if we can figure out how to test client auth/other ways to validate the cert we just assigned**
    - **Expected Behavior**
        - verify that SSA gives log message indicating that it is using the cert `keys/certificate_a.pem` file
        - verify that SSA gives log message indicating that it is using the private key `keys/key_a.pem` file
        - should get valid reponse from google **NOTE: this may be different if we can properly test the usage of the cert/key**
        - **TODO: figure out how to test/figure out certs were assigned correctly**
        - **TODO: figure out what client auth expected behavior should be**

2. Testing valid certificate with no private key assigned
    1. set `optname` to `TLS_CERTIFICATE_CHAIN`
    2. set `set_optval` to `keys/certificate_a.pem`
    3. comment out the code for setting `TLS_PRIVATE_KEY`
    4. run `make`
    5. run `./https_client www.google.com 443` **TODO: this may need to change if we can figure out how to test client auth/other ways to validate the cert we just assigned**
    - **Expected Behavior**
        - verify that SSA gives log message indicating that it is using the cert `keys/certificate_a.pem` file
        - **TODO: this should probably cause an error, but none given. Need to figure out that behavior and how to test it correctly**
        - **TODO: figure out what client auth expected behavior should be**

3. Testing assigning private key with no certificate
    1. set `optname` to `TLS_PRIVATE_KEY`
    2. set `set_optval` to `keys/key_a.pem`
    3. run `make`
    4. run `./https_client www.google.com 443` **TODO: this may need to change if we can figure out how to test client auth/other ways to validate the cert we just assigned**
    - **Expected Behavior**
        - verify that SSA gives log message indicating that it is using the private key `keys/key_a.pem` file
        - **TODO: this should probably cause an error, but none given. Need to figure out that behavior and how to test it correctly**
        - **TODO: figure out what client auth expected behavior should be**

4. Testing assigning certificate with wrong private key
    1. `optname` to `TLS_CERTIFICATE_CHAIN`
    2. `set_optval` to `keys/certificate_a.pem`
    3. `optname2` to `TLS_PRIVATE_KEY`
    4. `set_optval2`to `keys/key_b.pem`
    5. run `make`
    6. run `./https_client www.google.com 443` 
    - **Expected Behavior**
        - the client should return an error indicating failure, such as `Invalid argument`
5. Testing bad file path to cert
    1. set `optname` to `TLS_CERTIFICATE_CHAIN`
    2. set `set_optval` to `key/certificate_a.pem`
    3. run `make`
    4. run `./https_client www.google.com 443` 
    - **Expected Behavior** 
        - from the SSA logs, you should get an error like `ERROR:   Unable to assign certificate chain`
        - the client print an error
        - **TODO: currently the client segfaults instead of returning an error. Need to get the proper client behavior when this gets fixed**
        
#### TLS_TRUSTED_PEER_CERTIFICATES
**TODO: add tests and expected behavior**

#### TLS_ALPN
1. Test getsockopt with TLS_ALPN before connect
    1. Comment out the code for `setsockopt`, leaving only code for `getsockopt` to make consistent testing
    2. set `optname` to `TLS_ALPN`
    3. run `make`
    4. run ```/https_client www.google.com 443```
        - **Expected Behavior**
            - the SSA crashes **TODO: this seems like a bad things, so figure out what correct behavior is when this issue gets fixed**
            - the client returns an error "no buffer space available" **TODO: this is mostly likely because the SSA crashes, and this should change when we fix that behavior**
2. Test getsockopt with TLS_ALPN after connect
    1. copy or move getsockopt code until after connect (in my code, that is after line 82
    2. run `make`
    3. run ```/https_client www.google.com 443```
        - **Expected Behavior**
            - **TODO: figure out what expected behavior should be, currently I get a value of '' after connecting, even if I set it, which seems wrong but may be right**
3. Test setsockopt with TLS_ALPN:
    1. uncomment code for setsockopt done in step 1
    2. run `make`
    3. run ```/https_client www.google.com 443```
        - **Expected Behavior**
            - **TODO: figure out what expected behavior should be, currently I get a value of '' after connecting, even if I set it, which seems wrong but may be right**
4. Remove the code copied from step 2 if you copied or, or move it back to where it was before you moved it in step 3


#### TLS_SESSION_TTL
**TODO: add tests and expected behavior**

#### TLS_DISABLE_CIPHER
For these tests, you will need to change the admin settings in the ssa.cfg.
- Set `CipherSuite` to ```CipherSuite: "RSA:DH"``` in the `ssa.cfg` and restart the SSA


1. Test that getsockopt fails with TLS_DISABLE_CIPHER
    1. set `optname` to `TLS_DISABLE_CIPHER`
    2. set `set_optval` to `DH`
    3. run `make`
    4. run `./https_client rsa4096.badssl.com 443`
    - **Expected Behavior** 
        - you should get an error `Protocol not available` when using getsockopt and `TLS_DISABLE_CIPHER`
2. Test disabling a cipher
    1. Comment out the code for `getsockopt`, leaving only code for `setsockopt` because `TLS_DISABLE_CIPHER` only works with setsockopt, and returns an error if you use getsockopt.
    2. set `optname` to `TLS_DISABLE_CIPHER`
    3. set `set_optval` to `DH`
    4. run `make`
    4. run ```/https_client rsa4096.badssl.com 443```
        - **Expected Behavior**
            - from the client: get html content
            - from the SSA: no error logs
    5. run ```./https_client dh2048.badssl.com 443```
        - **Expected Behavior**
            - from the client: get error output, similar to ```connect: No route to host failed to find a suitable address for connection```
            - from the SSA: should get some error log similar to ```ERROR:   SSL error from bufferevent: ssl3_read_bytes [sslv3 alert handshake failure]```
3. Reset SSA and code back to normal
    1. Set `CipherSuite` in `ssa.cfg` back to what it was starting TLS_DISABLE_CIPHER tests
    2. Uncomment the code for getsockopt for future tests.

#### TLS_PEER_IDENTITY
1. Test that setsockopt fails with TLS_PEER_IDENTITY
    1. set `optname` to `TLS_PEER_IDENTITY`
    2. set `set_optval` to `blahblah` (the value doesn't matter)
    3. run `make`
    4. run `./https_client www.google.com 443`
    - **Expected Behavior** 
        - you should get an error `Protocol not available` when using setsockopt and `TLS_PEER_IDENTITY`
2. Test getting peer identity before connect
    1. Comment out the code for `setsockopt`, leaving only code for `getsockopt` because `TLS_PEER_IDENTITY` only works with getsockopt, and returns an error if you use setsockopt.
    2. set `optname` to `TLS_PEER_IDENTITY`
    4. run `make`
    4. run ```/https_client www.google.com 443```
        - **Expected Behavior**
            - the SSA crashes **TODO: this seems like a bad things, so figure out what correct behavior is when this issue gets fixed**
            - the client returns an error "no buffer space available" **TODO: this is mostly likely because the SSA crashes, and this should change when we fix that behavior**
3. Test getting peer identity after connect
    1. copy or move getsockopt code until after connect (in my code, that is after line 82
    4. run `make`
    4. run ```/https_client www.google.com 443```
        - **Expected Behavior**
            - you should get similar output to this `Used getsockopt: get_optval ='/C=US/ST=California/L=Mountain View/O=Google LLC/CN=www.google.com'`
4. Remove the code copied from step 3 if you copied or, or move it back to where it was before you moved it in step 3


#### TLS_PEER_CERTIFICATE_CHAIN
1. Test that setsockopt fails with TLS_PEER_CERTIFICATE_CHAIN
    1. set `optname` to `TLS_PEER_CERTIFICATE_CHAIN`
    2. set `set_optval` to `blahblah` (the value doesn't matter)
    3. run `make`
    4. run `./https_client www.google.com 443`
    - **Expected Behavior** 
        - you should get an error `Protocol not available` when using setsockopt and `TLS_PEER_CERTIFICATE_CHAIN`
2. Test getting peer certificate chain before connect
    1. Comment out the code for `setsockopt`, leaving only code for `getsockopt` because `TLS_PEER_CERTIFICATE_CHAIN` only works with getsockopt, and returns an error if you use setsockopt.
    2. set `optname` to `TLS_PEER_CERTIFICATE_CHAIN`
    4. run `make`
    4. run ```/https_client www.google.com 443```
        - **Expected Behavior**
            - the SSA crashes **TODO: this seems like a bad things, so 
            - from the SSA: no error logs
3. Test getting peer certificate chain after connect
    1. copy or move getsockopt code until after connect (in my code, that is after line 82
    4. run `make`
    4. run ```/https_client www.google.com 443```
        - **Expected Behavior**
            - You should see a line saying "peer identity: ---begin certificate --- ... ---end certficate---
4. Remove the code copied from step 3 if you copied or, or move it back to where it was before you moved it in step 3

## Server Testing

### Basic Server Functionality
To test basic SSA server functionality, go to `test_files/manual tests/` folder in the ssa-daemon and do the following:
1. Make sure the SSA is running
2. Make sure the server has the the lines in them (in case they were changed in other tests)
```
if (setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, CERT_FILE_A, sizeof(CERT_FILE_A)) == -1) {
    perror("cert a");
}
if (setsockopt(fd, IPPROTO_TLS, TLS_PRIVATE_KEY, KEY_FILE_A, sizeof(KEY_FILE_A)) == -1) {
    perror("key a");
}
if (setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, CERT_FILE_B, sizeof(CERT_FILE_B)) == -1) {
    perror("cert b");
}
if (setsockopt(fd, IPPROTO_TLS, TLS_PRIVATE_KEY, KEY_FILE_B, sizeof(KEY_FILE_B)) == -1) {
    perror("key b");
}

```
3. Run `make` to build the client and server
4. Run `./echo_server 8000` to run the server on port 8000. **Note:** the port is arbitrary, it can be any port)
5. Run `./https_client localhost 8000` to connect to you local server. Make sure your port is the same as the port set for the server.

**Expected Result**
1. Server 
    - server should get an output similar to the following 
    ```
    [pbstrein@ilab3 manual_tests]$ ./echo_server 8000
     Client requested host 10 localhost
     Echo client data: GET / HTTP/1.1
     host: localhost
      
      
     finished sending response
    ```
2. Client
    - should get the following things
        1. a peer certficiate
        2. A peer identity similar to the following `/C=US/ST=Utah/L=Provo/O=Default Company Ltd/CN=localhost`
        3. The following response
        ```
        Received:
        GET / HTTP/1.1
        host: localhost
        ```
        
### Server Socket Options

#### TLS_REMOTE_HOSTNAME
**TODO: add tests and expected behavior**

#### TLS_HOSTNAME
**TODO: add tests and expected behavior**

#### TLS_CERTIFICATE_CHAIN and TLS_PRIVATE_KEY
**TODO: add tests and expected behavior**

#### TLS_TRUSTED_PEER_CERTIFICATES
**TODO: add tests and expected behavior**

#### TLS_ALPN
**TODO: add tests and expected behavior**

#### TLS_SESSION_TTL
**TODO: add tests and expected behavior**

#### TLS_DISABLE_CIPHER
**TODO: add tests and expected behavior**

#### TLS_PEER_IDENTITY
**TODO: add tests and expected behavior**

#### TLS_PEER_CERTIFICATE_CHAIN
**TODO: add tests and expected behavior**
