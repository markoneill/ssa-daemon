#include "session_manager.h"

SSL_SESSION *session;

// Comm
void set_session(SSL_SESSION *sess){
	//printf("%x\n", sess);
	session = sess;
}

SSL_SESSION* get_session(){
	//printf("%x\n", session);
	return session;
}