#include <openssl/ssl.h>
#include "hashmap_str.h"

void set_session(SSL_SESSION *sess);
SSL_SESSION* get_session();
