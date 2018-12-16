#ifdef CLIENT_AUTH
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>

#define BDADDR_ANY   (&(bdaddr_t) {{0, 0, 0, 0, 0, 0}})
#define BDADDR_DEFAULT   (&(bdaddr_t) {{1, 2, 3, 4, 5, 6}})
#define BDADDR_DEST_DEFAULT "01:02:03:04:05:06";
#define BDADDR_DESTINATION "00:1A:7D:DA:71:13";

bdaddr_t* str2bamason(char* addr)
{
	
	bdaddr_t* bdaddr;
	char* token;
	int count = 0;
        const char* delim = ":";
	bdaddr = (bdaddr_t*) malloc(sizeof(bdaddr_t));
        token = strtok(addr,delim);
        while( token != NULL || count < 6)
        {
                bdaddr->b[count++] = strtol(token,NULL,16);
		token = strtok(NULL,delim);
        }
	printf("%d:%d:%d:%d:%d:%d", bdaddr->b[0],bdaddr->b[1],bdaddr->b[2],bdaddr->b[3],bdaddr->b[4],bdaddr->b[5]);
	return bdaddr;

        //sprintf(buf,"%d:%d:%d:%d:%d:%d", bdaddr->b[0],bdaddr->b[1],bdaddr->b[2],bdaddr->b[3],bdaddr->b[4],bdaddr->b[5]);
}


int main(int argc, char **argv)
{
    struct sockaddr_rc addr = { 0 };
    bdaddr_t* bdaddrPoint;
    int s, status;
    //char dest[18] = "01:23:45:67:89:AB";
    //char dest[18] = BDADDR_DESTINATION;
    char dest[18] = BDADDR_DEST_DEFAULT;

    // allocate a socket
    s = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);

    // set the connection parameters (who to connect to)
    addr.rc_family = AF_BLUETOOTH;
    addr.rc_channel = (uint8_t) 1;
    //addr.rc_bdaddr = *str2bamason(dest);
    addr.rc_bdaddr = *BDADDR_DEFAULT;
    printf("bdaddr from string = %02x:%02x:%02x:%02x:%02x:%02x\n",addr.rc_bdaddr.b[0],addr.rc_bdaddr.b[1],addr.rc_bdaddr.b[2],addr.rc_bdaddr.b[3],addr.rc_bdaddr.b[4],addr.rc_bdaddr.b[5]);
    //bdaddrPoint = strtoba( dest);
    //addr.rc_bdaddr = *bdaddrPoint;
    //addr.rc_bdaddr = *strtoba(dest);

    //strtoba( dest, &addr.rc_bdaddr );

    // connect to server
    status = connect(s, (struct sockaddr *)&addr, sizeof(addr));
    printf("After Connect\n");

    // send a message
    if( status == 0 ) {
        status = write(s, "hello!", 6);
    }

    if( status < 0 ) perror("uh oh");

    close(s);
    return 0;
}
#endif /* CLIENT_AUTH */
