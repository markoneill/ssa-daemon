#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include <sys/unistd.h>

#include "unix_server.h"

int global_fd;
struct sockaddr_un destination_address;

void chopString(char *str, size_t n)
{
    assert(n != 0 && str != 0);
    size_t len = strlen(str);
    if (n > len)
        return;  // Or: n = len;
    memmove(str, str+n, len - n + 1);
}

int create_unix_socket(){
	int fd;
	struct sockaddr_un addr;
	// create unix socket
	if ((fd = socket(PF_UNIX, SOCK_DGRAM, 0)) < 0) {
		perror("create socket failed");
		return -1;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, SERVER_SOCK_FILE);
	unlink(SERVER_SOCK_FILE);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind failed");
		return -1;
	}
	global_fd = fd;
	return fd;
}

int unix_recv(evutil_socket_t fd, short events, void *arg) {
	tls_daemon_ctx_t* ctx = (tls_daemon_ctx_t*)arg;
	int unix_fd;
	int ret;
	int len;
	int level;
	int optname;
	int blocking;
	char buff[8192];
	struct sockaddr_un from;
	socklen_t fromlen = sizeof(from);
	unsigned long id;
	char comm[PATH_MAX];
	char *id_ptr;
	char *level_ptr;
	char *optname_ptr;
	char* optval;
	char *blocking_ptr;
	socklen_t optlen;

	struct sockaddr_in addr_internal;
	struct sockaddr_in addr_external;
	struct sockaddr_in addr_remote;

	unix_fd = global_fd;
	len = recvfrom(unix_fd, buff, 8192, 0, (struct sockaddr *)&from, &fromlen);// get rid of the shile loop
	if(len < 0){
		perror("message receive failed");
		return -1;
	}
	destination_address = from;
	if(buff[0] == '1'){ // a socket notify
		if(buff[1] == 'i' && buff[2] == 'd'){
			char *ptr;
			chopString(buff, 3);
			id = strtoul(buff, &ptr, 10);
			printf("Received socket notification with id number: %s\n", buff);
		}
		else if(buff[1] == 'p' && buff[2] == 'a'){ // last message to receive
            chopString(buff, 3);
            printf("Received client path: %s\n", buff);
            memcpy(comm, buff, sizeof(buff));
            socket_cb(ctx, id, comm);
		}
		else{
			printf("received socket notification\n");
		}
	}
	else if(buff[0] == '2'){ // a set sockopt notification 
		if(buff[1] == 'i' && buff[2] == 'd'){
			chopString(buff, 3);
			id = strtoul(buff, &id_ptr, 10);
			printf("Received set sockopt notification with id number: %s\n", buff);
		}
		else if(buff[1] == 'l' && buff[2] == 'e'){
			chopString(buff, 3);
			level = strtoul(buff, &level_ptr, 10);
			printf("Received set sockopt notification with level number: %s\n", buff);
		}
		else if(buff[1] == 'o' && buff[2] == 'n'){
			chopString(buff, 3);
			optname = strtoul(buff, &optname_ptr, 10);
			printf("Received option name: %s in set sockopt notification.\n", buff);
		}
		else if(buff[1] == 'o' && buff[2] == 'v'){
			chopString(buff, 3);
			strcpy(optval, buff);
			optlen = sizeof(optval);
			setsockopt_cb(ctx, id, level, optname, optval, optlen);
			printf("Received option value %s in set sockopt notification\n", buff);

		}
		else{
			printf("received set sockopt notification\n");
			strcpy (buff, "received setsockopt notification");
	   		ret = sendto(fd, buff, strlen(buff)+1, 0, (struct sockaddr *)&from, fromlen);
	   		if (ret < 0) {
		 	perror("failed in sendto");
		 	return -1;
	        } 
		}
	}
	else if(buff[0] == '3'){ // connection notification
		if(buff[1] == 'i' && buff[2] == 'd'){
			chopString(buff, 3);
			id = strtoul(buff, &id_ptr, 10);
			printf("Received id number: %s in connection\n", buff);
		}
		else if(buff[1] == 'l' && buff[2] == 'a'){
			chopString(buff, 3);
			printf("Received local address: %s in connection\n", buff);
		}
		else if(buff[1] == 'r' && buff[2] == 'a'){
			chopString(buff, 3);
			printf("Received remote address: %s in connection\n", buff);
		}
		else if(buff[1] == 'b' && buff[2] == 'n'){
			chopString(buff, 3);
			blocking = strtoul(buff, &blocking_ptr, 10);
			printf("Received block number: %s in connection\n", buff);
		}
		else{
			printf("Received connection notification\n");
            strcpy (buff, "received connection notification");
	   		ret = sendto(fd, buff, strlen(buff)+1, 0, (struct sockaddr *)&from, fromlen); // destination address
	   		printf ("dentination address after send: %s\n", from);
	   		if (ret < 0) {
		 	perror("failed in sendto");
		 	return -1;
	   		} 
		}
	}
	else if(buff[0] == '4'){ // get sock opt
		if(buff[1] == 'i' && buff[2] == 'd'){
			chopString(buff, 3);
			id = strtoul(buff, &id_ptr, 10);
            printf("Received id: %s in getsockopt\n", buff);
		}
		else if(buff[1] == 'l' && buff[2] == 'e'){
			chopString(buff, 3);
			level = strtoul(buff, &level_ptr, 10);
			printf("Received level: %s in getsockopt\n", buff);
		}
		else if(buff[1] == 'o' && buff[2] == 'n'){
			chopString(buff, 3);
			optname = strtoul(buff, &optname_ptr, 10);
			printf("Received option number: %s in getsockopt\n", buff);
			//get the option name
		}
		else{
			printf("Received getsockopt notification\n");
            strcpy (buff, "received getsockopt notification");
		    ret = sendto(fd, buff, strlen(buff)+1, 0, (struct sockaddr *)&from, fromlen); // destination address
		    printf ("dentination address after send: %s\n", from);
		    if (ret < 0) {
			perror("failed in sendto");
			return -1;
	        } 
		}
	}
	else{
	   printf("Received close notification\n");
       strcpy (buff, "received close notification");
	   //ret = sendto(fd, buff, strlen(buff)+1, 0, (struct sockaddr *)&from, fromlen); // destination address
	   //printf ("dentination address after send: %s\n", from);
	   //if (ret < 0) {
	   //perror("failed in sendto");
	   //return -1;
	   //}
	}

	return 0;
}

int close_unix_socket(int fd){
    return close(fd);
}

// type one need to send a id and response back
void unix_notify_kernel(tls_daemon_ctx_t* ctx, unsigned long id, int response) {
	int ret;
	int fd;
	char idString[256];
    char responseString[256];
    char result[256];
    char buff[8192];
	socklen_t len = sizeof(destination_address);

	fd = global_fd;

    strcpy(result, "1");
    sprintf(idString, "%ld", id);
    sprintf(responseString, "%ld", response);
    strcat(result, responseString); // append response
    strcat(result, idString); // append id 
    strcpy(buff, result);
    ret = sendto(fd, buff, strlen(buff)+1, 0, (struct sockaddr *)&destination_address, len);
    if (ret < 0) {
    perror("failed in sendto");
    return;
    }
    else{
    	printf("message send success in socket\n");
    }
	return;
}

//type two need to send id and data back
void unix_send_and_notify_kernel(tls_daemon_ctx_t* ctx, unsigned long id, char* data, unsigned int len) {
	int ret;
	int fd;
    char idString[256];
    char result[256];
    char buff[8192];
    socklen_t address_len = sizeof(destination_address);

    fd = global_fd;

    strcpy(result, "2");
    sprintf(idString, "%ld", id);
    strcat(result, idString); // append id
    strcat(result, data); // append data
    strcpy(buff, result);
    ret = sendto(fd, buff, strlen(buff)+1, 0, (struct sockaddr *)&destination_address, address_len);
    if (ret < 0) {
    perror("failed in sendto");
    return;
    }
    else{
    	printf("message send success in socket\n");
    }
	return;
}

//type 3 is the hand shake response
void unix_handshake_notify_kernel(tls_daemon_ctx_t* ctx, unsigned long id, int response) {
	int ret;
    int fd;
	char idString[256];
    char responseString[256];
    char result[256];
    char buff[8192];
	socklen_t len = sizeof(destination_address);

	fd = global_fd;

    strcpy(result, "1");
    sprintf(idString, "%ld", id);
    sprintf(responseString, "%ld", response);
    strcat(result, responseString); // append response
    strcat(result, idString); // append id 
    strcpy(buff, result);
    ret = sendto(fd, buff, strlen(buff)+1, 0, (struct sockaddr *)&destination_address, len);
    if (ret < 0) {
    perror("failed in sendto");
    return;
    }
    else{
    	printf("message send success in socket\n");
    }
	return;
}