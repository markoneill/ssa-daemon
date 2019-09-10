# User Documentation

## Purpose 
The purpose of this README is to show how to use the SSA, with examples of client and server code. It also includes explanations of the socket functions and the different socket options.

This README is not comprehensive, and if any details are missing, please add them.

## Table of Contents
- [Pre-requisites](#pre-requisites)
- [Using the SSA](#using-the-ssa)
    - [Creating a Client](#creating-a-client)
    - [Creating a Server](#creating-a-server)
    - [Examples](#examples)
        - [Example HTTPS Client](#example-https-client)
        - [Example Client and Server](#example-client-and-server)
            - [Simple Echo Server](#simple-echo-server)
            - [Simple Client](#simple-client)
- [SSA Socket Function and Behavior](#ssa-socket-functions-and-behavior)
- [Socket Options for SSA](#socket-options-for-ssa)

## Pre-requisites 
Follow the instructions to install the ssa-daemon and the ssa-kernel.

## Using the SSA
Once you have run the kernel module and have the daemon running, the SSA will intercept and handle any traffic that use the `IPPROTO_TLS` socket type. From there, it similar to writing normal socket code. 

### Creating a Client
A client using the SSA is no different from a regular TCP/UDP client except that you use the socekt type `IPPROTO_TLS`. Connecting to a server and writing to the server is no different. 

See the [example https client](#example-https-client) below for client usage. 

See the [SSA Socket Functions and Behavior](#ssa-socket-functions-and-behavior) socket descriptions to see how the socket functions behavior is different with `IPPROTO_TLS`

### Creating a Server

A server using `IPPROTO_TLS` is exactly the same as a regular TCP/UDP server except for the following things:
1. You must assign a certificate chain to the server using `setsockipt` with the option `TLS_CERTIFICATE_CHAIN`
    - example `setsockopt(fd, IPPROTO_TLS ,TLS_CERTIFICATE_CHAIN ,CERT_FILE , sizeof(CERT_FILE));` where `fd` is the listening fd and `CERT_FILE` is the path to the cert
2. You must assign a private key to the server using `setsockopt` with the option `TLS_PRIVATE_KEY`
    - example `setsockopt(fd, IPPROTO_TLS , TLS_PRIVATE_KEY ,KEY_FILE , sizeof(KEY_FILE));`
    
For more examples of server usage, see [Simple Echo Server](#simple-echo-server)

See the [SSA Socket Functions and Behavior](#ssa-socket-functions-and-behavior) socket descriptions to see how the socket functions behavior is different with `IPPROTO_TLS`

### Examples

#### Example HTTPS Client
Below is code for an example client that can make HTTPS connections to any HTTPS server. 
	Note: This code can only be run as is if you save this test file in either ssa-daemon/test_files/https_server or ssa-daemon/test_files/https_client or any other folder that is 2 down the file path from in_tls.h
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include "../../in_tls.h" //This will need to be changed if this example HTTPS Client is saved anywhere other than the ssa-daemon/test_files/https_client folder. 

#define MAX_REQUEST_SIZE 2048
#define MAX_RESPONSE_SIZE 2048

void print_identity(int fd);

int main(int argc, char* argv[]) {
	int sock_fd;
	int ret;
	char http_request[MAX_REQUEST_SIZE];
	char http_response[MAX_RESPONSE_SIZE];
	struct addrinfo hints;
	struct addrinfo* addr_ptr;
	struct addrinfo* addr_list;

	if (argc < 2) {
		printf("USAGE: %s <host name>\n", argv[0]);
		return 0;
	}

    char* host = argv[1];
    char* port = "443"; //default to 443 for HTTPS connections

    //set up the connection
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;
	ret = getaddrinfo(host, port, &hints, &addr_list);
	if (ret != 0) {
		fprintf(stderr, "Failed in getaddrinfo: %s\n", gai_strerror(ret));
		exit(EXIT_FAILURE);
	}

    //connect to the port
	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {
		sock_fd = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, IPPROTO_TLS);
		if (sock_fd == -1) {
			perror("socket");
			continue;
		}

        //set the correct hostname for correct handshake
        if (setsockopt(sock_fd, IPPROTO_TLS, TLS_REMOTE_HOSTNAME, host, strlen(host)+1) == -1) {
			perror("setsockopt: TLS_REMOTE_HOSTNAME");
			close(sock_fd);
			continue;
		}

        //connect to the socket
		if (connect(sock_fd, addr_ptr->ai_addr, addr_ptr->ai_addrlen) == -1) {
			perror("connect");
			close(sock_fd);
			continue;
		}
		break;
	}

	freeaddrinfo(addr_list);
	if (addr_ptr == NULL) {
		fprintf(stderr, "failed to find a suitable address for connection\n");
		exit(EXIT_FAILURE);
	}

    //put the HTTP request into the buf
	sprintf(http_request,"GET / HTTP/1.1\r\nhost: %s\r\n\r\n", argv[1]);
	memset(http_response, 0, 2048);
    
    //send encrypted request
    int request_size = strlen(http_request);
    int tot_bytes_sent = 0;
    while(tot_bytes_sent < request_size) {
        int bytes_sent = send(sock_fd, http_request + tot_bytes_sent, request_size - tot_bytes_sent, 0);
        tot_bytes_sent += bytes_sent;
    }

    // receive decrypted response
    // in general, more robust reading will be required
	recv(sock_fd, http_response, MAX_RESPONSE_SIZE, 0);
	printf("Received:\n%s\n", http_response);
	close(sock_fd);
	return 0;
}
``` 
##### Running Example Code
1. Compile code running `gcc -o https_client https_client.c`
2. Run `./https_client www.google.com` to connect to google. You can replace the URL with any HTTPS server. 

You should get an HTML response from the server. 

##### Analysis
The code looks similar to regular socket code. There are some important differences. 
1. `#include "../../in_tls.h"` - this gets the appropiate headers to be able to use the SSA, for example `IPPROTO_TLS` is found in those headers. In your code, you will need to reference the headers wherever they are located on your machine.
2. `char* port = "443";` - HTTPS communicates via port 443 instead of port 80
3. `sock_fd = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, IPPROTO_TLS);` - instead of using `IPPROTO_TCP` it used `IPPROTO_TLS` to signify a secure connection via the SSA
4. `if (setsockopt(sock_fd, IPPROTO_TLS, TLS_REMOTE_HOSTNAME, host, strlen(host)+1) == -1) {` - used the socket option `TLS_REMOTE_HOSTNAME` to correctly certify the host using OpenSSL.

Everything else is the same as with regular socket code. 

**Note** `sprintf(http_request,"GET / HTTP/1.1\r\nhost: %s\r\n\r\n", argv[1]);` creates a regular HTTP request, even though it is HTTPS. That is because all the TLS and OpenSSL functionality is handled by the SSA.

#### Example Client and Server

##### Simple Echo Server
The following code creates a simple echo server using IPPROTO_TLS
	Note: This code can only be run as is if you save this test file in either ssa-daemon/test_files/https_server or ssa-daemon/test_files/https_client or any other folder that is 2 down the file path from in_tls.h
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include "../../in_tls.h" //This will need to be changed if this example HTTPS Client is saved anywhere other than the ssa-daemon/test_files/https_server folder.

#define CERT_FILE_A	"keys/certificate_a.pem"
#define KEY_FILE_A	"keys/key_a.pem"
#define CERT_FILE_B	"keys/certificate_b.pem"
#define KEY_FILE_B	"keys/key_b.pem"
#define BUFFER_SIZE	2048

void handle_req(char* req, char* resp);

int main(int argc, char* argv[]) {

    if (argc < 2) {
        printf("USAGE: %s <port>\n", argv[0]);
        exit(1);
    }
    int port = atoi(argv[1]);

	char servername[255];
	int servername_len = sizeof(servername);
	char request[BUFFER_SIZE];
	char response[BUFFER_SIZE];
	memset(request, 0, BUFFER_SIZE);

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("0.0.0.0");
	addr.sin_port = htons(port);

	int fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TLS);
	bind(fd, (struct sockaddr*)&addr, sizeof(addr));
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
	listen(fd, SOMAXCONN);

	while (1) {	
		struct sockaddr_storage addr;
		socklen_t addr_len = sizeof(addr);
		int c_fd = accept(fd, (struct sockaddr*)&addr, &addr_len);
		if (getsockopt(c_fd, IPPROTO_TLS, TLS_HOSTNAME, servername, &servername_len) == -1) {
			perror("getsockopt: TLS_HOSTNAME");
			exit(EXIT_FAILURE);
		}
		printf("Client requested host %d %s\n", servername_len,  servername);
		recv(c_fd, request, BUFFER_SIZE, 0);
		handle_req(request, response);
		send(c_fd, response, BUFFER_SIZE, 0);
		close(c_fd);
	}
	return 0;
}

void handle_req(char* req, char* resp) {
	memcpy(resp, req, BUFFER_SIZE);
    printf("Echo client data: %s\n", req);
    sprintf(resp, "%s", req);
	return;
}
```

##### Running the Echo Server
To run this code, do the following:
1. Compile the code (ie `gcc -o echo_server echo_server.c`)
2. Run `./echo_server 1080` where 1080 is the port you run on

Now you have a server listening on port 1080 for secure connections.

##### Simple Client
The code below gives a simple client to connect to the echo server above. 
This client is nearly identical to the https client above. The only difference is you can specify the port to help connect to ports other than 443.
	Note: This code can only be run as is if you save this test file in either ssa-daemon/test_files/https_server or ssa-daemon/test_files/https_client or any other folder that is 2 down the file path from in_tls.h

```c 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include "../../in_tls.h"//This will need to be changed if this example HTTPS Client is saved anywhere other than the ssa-daemon/test_files/https_client folder.

#define MAX_REQUEST_SIZE 2048
#define MAX_RESPONSE_SIZE 2048

void print_identity(int fd);

int main(int argc, char* argv[]) {
	int sock_fd;
	int ret;
	char http_request[MAX_REQUEST_SIZE];
	char http_response[MAX_RESPONSE_SIZE];
	struct addrinfo hints;
	struct addrinfo* addr_ptr;
	struct addrinfo* addr_list;

	if (argc < 3) {
		printf("USAGE: %s <host name> <port>\n", argv[0]);
		return 0;
	}

    char* host = argv[1];
    char* port = argv[2]; 

    //set up the connection
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;
	ret = getaddrinfo(host, port, &hints, &addr_list);
	if (ret != 0) {
		fprintf(stderr, "Failed in getaddrinfo: %s\n", gai_strerror(ret));
		exit(EXIT_FAILURE);
	}

    //connect to the port
	for (addr_ptr = addr_list; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {
		sock_fd = socket(addr_ptr->ai_family, addr_ptr->ai_socktype, IPPROTO_TLS);
		if (sock_fd == -1) {
			perror("socket");
			continue;
		}

        //set the correct hostname for correct handshake
        if (setsockopt(sock_fd, IPPROTO_TLS, TLS_REMOTE_HOSTNAME, host, strlen(host)+1) == -1) {
			perror("setsockopt: TLS_REMOTE_HOSTNAME");
			close(sock_fd);
			continue;
		}

        //connect to the socket
		if (connect(sock_fd, addr_ptr->ai_addr, addr_ptr->ai_addrlen) == -1) {
			perror("connect");
			close(sock_fd);
			continue;
		}
		break;
	}

	freeaddrinfo(addr_list);
	if (addr_ptr == NULL) {
		fprintf(stderr, "failed to find a suitable address for connection\n");
		exit(EXIT_FAILURE);
	}

    //put the HTTP request into the buf
	sprintf(http_request,"GET / HTTP/1.1\r\nhost: %s\r\n\r\n", argv[1]);
	memset(http_response, 0, 2048);
    
    //send encrypted request
    int request_size = strlen(http_request);
    int tot_bytes_sent = 0;
    while(tot_bytes_sent < request_size) {
        int bytes_sent = send(sock_fd, http_request + tot_bytes_sent, request_size - tot_bytes_sent, 0);
        tot_bytes_sent += bytes_sent;
    }

    // receive decrypted response
    // in general, more robust reading will be required
	recv(sock_fd, http_response, MAX_RESPONSE_SIZE, 0);
	printf("Received:\n%s\n", http_response);
	close(sock_fd);
	return 0;
}
```
##### Running the Client
To connect to the server using the client, do the following:
1. Compile the client (ie `gcc -o client client.c`)
2. Run the client with `./client localhost 1080` where `localhost` is the address of the server and `1080` is the port of the server

You should get a result similar to the following:
```bash
[pbstrein@ilab3 manual_tests]$ ./https_client localhost 1080
Received:
GET / HTTP/1.1
host: localhost
```

## SSA Socket Functions and Behavior
Here we give brief descriptions of the behavior of POSIX socket functions generally and under IPPROTO_TLS specifically. General behavior is paraphrased from relevant manpages.

| POSIX Function      | General Behavior           | Behavior under IPPROTO_TLS  |
| ------------------|:-------------|:-----|
| socket            | Create an endpoint for communication utilizing the given protocol family, type, and optionally a specific protocol.| Create an endpoint for TLS communication, which utilizes TCP for its transport protocol if the `type` parameter is `SOCK_STREAM` and uses DTLS over UDP if `type` is `SOCK_DGRAM`. |
| connect           | Connect the socket to the address specifiedby the `addr` parameter for stream protocols, or indicate a destination address for subsequent transmissions for datagram protocols.     |  Perform  a  connection  for  the  underlying transport protocol if applicable (e.g.,  TCP handshake),  and  perform  the  TLS  handshake  (client-side)  with  the  specified  remote address. Certificate and hostname validation is performed according to administrator and as optionally specified by the application via setsockopt.|
| bind              | Bind the socket to a given local address.      |    No TLS-specific behavior |
| listen            | Mark   a   connection-based   socket   (e.g.,`SOCK_STREAM`)  as  a  passive  socket  to  be used for accepting incoming connections.      |  No TLS-specific behavior |
| accept            | Retrieve connection request from the pending  connections  of  a  listening  socket  and create a new socket descriptor for interactions with the remote endpoint.      |   Retrieve  a  connection  request  from  the pending   connections,   perform   the   TLS handshake  (server-side)  with  the  remote endpoint, and create a new descriptor for interactions with the remote endpoint.|
| send,sendto,etc.  | Transmit data to a remote endpoint. |    Encrypt and transmit data to a remote endpoint. |
| recv,recvfrom,etc.| Receive data from a remote endpoint.     |    Receive  and  decrypt  data  from  a  remote endpoint|
| shutdown          | Perform full or partial teardown of connec-tion, based on the `how` parameter.    |    Send a TLS close notify. |
| close             | Close  a  socket,  perform  connection  teardown if there are no remaining references to socket     |    Close a socket, send a TLS close notify, and tear-down connection, if applicable.|
| select,poll,etc.  | Wait for one or more descriptors to become ready for I/O operations     |    No TLS-specific behavior.|
| setsockopt        | Manipulate   options   associated   with   a socket, assigning values to specific options for  multiple  protocol  levels  of  the  OSI stack.     |    Manipulate TLS specific options when the `level` parameter is `IPPROTO_TLS`, such as specifying a certificate or private key to associate with the socket. Other `level` values interact with the socket according to their existing semantics|
| getsockopt        | Retrieve a value associated with an option from a socket, specified by the `level` and `option_name` parameters.     |    For  a `level_value`  of `IPPROTO_TLS`,  retrieve  TLS-specific  option  values.    Other `level` values  interact  with  the  socket  according to their existing semantics.|


## Socket Options for SSA

Here we give a sample of the socket options and their purpose that can be given to IPPROTO_TLS sockets by using `setsockopt` or `getsockopt`


| IPPROTO_TLS socket option        | Purpose           | 
| ------------- |:-------------| 
| TLS_REMOTE_HOSTNAME | Used to indicate the hostname of the remote host.  This option will cause the SSA to use the Server Name Indication in the TLS Client Hello message, and also use the specified hostname to verify the certificate in the TLS handshake. Use of the `AF_HOSTNAME` address type in `connect` will set this option automatically. | 
| TLS_HOSTNAME | Used to specify and retrieve the hostname of the local socket. Servers can use this option to multiplex incoming connections from clients requesting different hostnames (e.g., hosting multiple HTTPS sites on one port).      | 
| TLS_CERTIFICATE_CHAIN | Used to indicate the certificate (or chain of certificates) to be used for the TLS handshake. This option can be used by both servers and clients.  A single certificate may be used if there are no intermediate certificates to be used for the connection.  The value itself can be sent either as a path to a certificate file or an array of bytes, in PEM format. This option can be set multiple times to allow a server to use multiple certificates depending on the requests of the client.      | 
| TLS_PRIVATE_KEY | Used to indicate the private key associated with a previously indicated certificate.  The value of this option can either be a path to a key file or an array of bytes, in PEM format.  The SSA will report an error if the provided key does not match a provided certificate      | 
| TLS_TRUSTED_PEER_CERTIFICATES | Used to indicate one or more certificates to be a trust store for validating certificates sent by the remote peer. These can be leaf certificates that directly match the peer certificate and/or those that directly or indirectly sign the peer certificate. Note that in the presence or absence of this option, peer certificates are still validated according to system policy      | 
| TLS_ALPN | Used to indicate a list of IANA-registered protocols for Application-Layer Protocol Negotiation (e.g., HTTP/2), in descending order of preference.  This option can be fetched after `connect`/`accept` to determine the selected protocol.      | 
| TLS_SESSION_TTL | Request that the SSA expire sessions after the given number of seconds.   A value of zero disables session caching entirely.      | 
| TLS_DISABLE_CIPHER | Request that the underlying TLS connection not use the specified cipher      | 
| TLS_PEER_IDENTITY | Request the identity of remote peer as indicated by the peer’s certificate.     | 
| TLS_PEER_CERTIFICATE_CHAIN | Request the remote peer’s certificate chain in PEM format for custom inspection.     | 

For example, if you wanted to set the certificate chain for a server, you would use the following line of code. 

`setsockopt(fd, IPPROTO_TLS, TLS_CERTIFICATE_CHAIN, CERT_FILE_A, sizeof(CERT_FILE_A)`
where 
- `fd` is the socket file descriptor you are using
- `IPPROTO_TLS` is the socket level, indicating TLS
- `TLS_CERTIFICATE_CHAIN` is the option name, representing the option used to set a certificate chain
- `CERT_FILE_A` sets the value of the option, in this case it is the path to a certificate file
- `sizeof(CERT_FILE_A)` is the size of the option buffer
