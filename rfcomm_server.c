#ifdef CLIENT_AUTH
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>

#define BDADDR_DEFAULT   (&(bdaddr_t) {{1, 2, 3, 4, 5, 6}})

void ba2strmason(bdaddr_t* bdaddr, char* buf)
{
	sprintf(buf,"%02x:%02x:%02x:%02x:%02x:%02x", bdaddr->b[0],bdaddr->b[1],bdaddr->b[2],bdaddr->b[3],bdaddr->b[4],bdaddr->b[5]);
}

int main(int argc, char **argv)
{
    struct sockaddr_rc loc_addr = { 0 }, rem_addr = { 0 };
    char buf[1024] = { 0 };
    int sock, client, bytes_read;
    socklen_t opt = sizeof(rem_addr);

    // allocate socket
    sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);

    // bind socket to port 1 of the first available
    // local bluetooth adapter
    loc_addr.rc_family = AF_BLUETOOTH;
    //loc_addr.rc_bdaddr = *BDADDR_ANY;
    loc_addr.rc_bdaddr = *BDADDR_DEFAULT;
    loc_addr.rc_channel = (uint8_t) 1;
    bind(sock, (struct sockaddr *)&loc_addr, sizeof(loc_addr));

    ba2strmason( &loc_addr.rc_bdaddr, buf );
    printf("connection at addr= %s\n", buf);
    // put socket into listening mode
    listen(sock, 1);

    // accept one connection
    client = accept(sock, (struct sockaddr *)&rem_addr, &opt);

    ba2strmason( &rem_addr.rc_bdaddr, buf );
    fprintf(stderr, "accepted connection from %s\n", buf);
    memset(buf, 0, sizeof(buf));

    // read data from the client
    bytes_read = read(client, buf, sizeof(buf));
    if( bytes_read > 0 ) {
        printf("received [%s]\n", buf);
    }

    // close connection
    printf("closing connection");
    close(client);
    close(sock);
    return 0;
}
#endif /* CLIENT_AUTH */
