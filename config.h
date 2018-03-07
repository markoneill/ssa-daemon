#ifndef CONFIG_H
#define CONFIG_H
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include "hashmap_str.h"
enum validation { Normal, TrustBase };
#define SSA_EXT_SNI    0x0001
#define SSA_EXT_ALPN   0x0002
#define SSA_EXT_TICKET 0x0004

typedef struct {
    char* profile;
    int min_version;
    int max_version;
    long options; //for version stuff too
    char* cipher_list;
    enum validation validate;
    char* trust_store;
    bool custom_validation;
    long cache_timeout;
    char* cache_path;
    long extensions; //bitmask
} ssa_config_t;

extern char DEFAULT_CONF[];
extern hsmap_t* global_config;
extern size_t global_config_size;

size_t parse_config(char* filename);
void free_config();
ssa_config_t* get_app_config(char* app_path);

#endif
