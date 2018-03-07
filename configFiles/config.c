#include "config.h"
#include "log.h"
#include "hashmap_str.h"
#include <libconfig.h>
#include <string.h>
#define MATCH(s, n) strcmp(s, n) == 0

void add_setting(ssa_config_t* config, config_setting_t* cur_setting) {
    const char* name = config_setting_name(cur_setting);
    const char* value;
    log_printf(LOG_DEBUG, "Parsing line: %s\n", name);
    if (MATCH(name, "Application")) {
        config->profile = strdup(config_setting_get_string(cur_setting));
    }
    else if (MATCH(name, "MinProtocol")) {
        value = config_setting_get_string(cur_setting);
        if (MATCH(value, "1.2")) {
            config->min_version = TLS1_2_VERSION;
        }
        else if (MATCH(value, "1.1")) {
            config->min_version = TLS1_1_VERSION;
        }
        else if (MATCH(value, "1.0")) {
            config->min_version = TLS1_VERSION;
        }
        else {
            log_printf(LOG_ERROR, "Unsupported MinVersion: %s\n", value);
        }
    }
    else if (MATCH(name, "CipherSuite")) {
        if (config->cipher_list != NULL)
            free(config->cipher_list);
        config->cipher_list = strdup(config_setting_get_string(cur_setting));
    }
    else if (MATCH(name, "SessionCacheTimeout")) {
        config->cache_timeout = config_setting_get_int(cur_setting);
    }
    else if (MATCH(name, "SessionCacheLocation")) {
        if (config->cache_path != NULL)
            free(config->cache_path);
        config->cache_path = strdup(config_setting_get_string(cur_setting));
    }
    else if (MATCH(name, "Validation")) {
        value = config_setting_get_string(cur_setting);
        if (MATCH(value, "Normal")) {
            config->validate = Normal;
        }
        else {
            config->validate = TrustBase;
        }
    }
    else if (MATCH(name, "TrustStoreLocation")) {
        if (config->trust_store != NULL)
            free(config->trust_store);
        config->trust_store = strdup(config_setting_get_string(cur_setting));
    }
    else if (MATCH(name, "AppCustomValidation")) {
        value = config_setting_get_string(cur_setting);
        config->custom_validation = 0;
        if (MATCH(value, "On")) {
            config->custom_validation = 1;
        }
    }
    else if (MATCH(name, "Extensions")) {
        int extension_count = config_setting_length(cur_setting);
        for(int i = 0; i < extension_count; i++) {
            const char* extension = config_setting_get_string_elem(cur_setting, i);
            if (MATCH(extension, "SNI")) {
                config->extensions |= SSA_EXT_SNI;
            } 
            else if (MATCH(extension, "ALPN")) {
                config->extensions |= SSA_EXT_ALPN;
            }
            else if (MATCH(extension, "TICKET")) {
                config->extensions |= SSA_EXT_TICKET;
            }
            else {
                log_printf(LOG_ERROR, "Unsupported Extension: %s\n", extension);
            }
        }
    }
    else {
        log_printf(LOG_ERROR, "Unsupported configline: %s\n", name);
    }
}

void init_ssa_config(ssa_config_t* def, ssa_config_t* cur) {
    cur->options           = def->options;
    cur->cipher_list       = strdup(def->cipher_list);
    cur->validate          = def->validate;
    cur->trust_store       = strdup(def->trust_store);
    cur->custom_validation = def->custom_validation;
    cur->cache_timeout     = def->cache_timeout;
    cur->cache_path        = strdup(def->cache_path);
    cur->extensions        = def->extensions;
    cur->min_version       = def->min_version;
    cur->max_version       = def->max_version;
}

void free_config_entry(void* config) {
    ssa_config_t* conf = (ssa_config_t*) config;

    // This is a little dirty becuase the profile is the key
    // the default profile is set to null so we don't need to worry about it.
    if ( (conf->profile != NULL) )
        free(conf->profile);
    if (conf->cipher_list != NULL)
        free(conf->cipher_list);
    if (conf->trust_store != NULL)
        free(conf->trust_store);
    if (conf->cache_path != NULL)
        free(conf->cache_path);
    free(conf);
}

void free_config()
{
    hashmap_deep_free(global_config,free_config_entry);
    global_config = NULL;
    global_config_size = 0;
}

size_t parse_config(char* filename) {
    free_config(); // Just incase you call parse_config multiple times
    config_t cfg;
    config_setting_t *default_profile;
    config_setting_t *cur_profile;
    config_setting_t *cur_setting;
    config_setting_t *profiles;
    ssa_config_t* default_config;
    ssa_config_t* cur_config;

    int num_profiles;
    const char* str;
    int myint;

    config_init(&cfg);

    if (!config_read_file(&cfg, filename)) {
        log_printf(LOG_ERROR, "Error loading config file %s: %s %d\n", filename, config_error_text(&cfg), config_error_line(&cfg));
        return -1;
    }

    profiles = config_lookup(&cfg, "Profiles");
    num_profiles = config_setting_length(profiles);
    
    // global_config = calloc(num_profiles + 1, sizeof(ssa_config_t));
    global_config = hashmap_create(20);
    default_config = calloc(1,sizeof(ssa_config_t));
    global_config_size = num_profiles + 1;
    
    // Parse default
    default_profile = config_lookup(&cfg, "Default");
    int default_i = config_setting_length(default_profile);
    for (int i = 0; i < default_i; i++) {
        add_setting(default_config, config_setting_get_elem(default_profile, i));
    }
    //Default profile does not need a name
    default_config->profile = NULL;
    hashmap_add(global_config,DEFAULT_CONF,default_config);



    /* //TODO check to make sure defaults are actually set
    if (config_lookup(&cfg, "Default.MinProtocol") == NULL) {
        //TODO error default not set
    }
    config_lookup(&cfg, "Default.CipherSuite", &str);
    config_lookup(&cfg, "Default.SessionCacheTimeout", &myint);
    config_lookup(&cfg, "Default.Validation", &str);
    config_lookup(&cfg, "Default.TrustStoreLocation", &str);
    config_lookup(&cfg, "Default.AppCustomValidation", &str);
    */
    // Parse all the profiles

    for(int i = 0; i < num_profiles; i++) {
        cur_config = malloc(sizeof(ssa_config_t));
        init_ssa_config(default_config, cur_config);
        cur_profile = config_setting_get_elem(profiles, i);
        int num_custom = config_setting_length(cur_profile);
        for (int j = 0; j < num_custom; j++) {
            cur_setting = config_setting_get_elem(cur_profile, j);
            add_setting(cur_config, cur_setting);
        }
        hashmap_add(global_config,cur_config->profile,cur_config);
    }

    hashmap_print(global_config);

    config_destroy(&cfg);
    return global_config_size;
}

void tests() {
    hsmap_t* map;
    char my_str[] = "This is a test string";
    char str1[] = "1";
    char str2[] = "2";
    char str3[] = "34";
    char str4[] = "35";
    char str5[] = "26";
    char str6[] = "17";
    map = hashmap_create(20);
    printf("Inserting test:%s\n", my_str);
    hashmap_add(map,my_str,my_str);
    printf("Inserting str1:%s\n", str1);
    hashmap_add(map,str1,str1);
    printf("Inserting str2:%s\n", str2);
    hashmap_add(map,str2,str2);
    printf("Inserting str3:%s\n", str3);
    hashmap_add(map,str3,str3);
    printf("Inserting str4:%s\n", str4);
    hashmap_add(map,str4,str4);
    printf("Inserting str5:%s\n", str5);
    hashmap_add(map,str5,str5);
    printf("Inserting str6:%s\n", str6);
    hashmap_add(map,str6,str6);
    hashmap_print(map);

    printf("\n\nGET STRINGS\n");
    printf("Get my_str:%s\n", (char*)hashmap_get(map,my_str));
    printf("Get str1:%s\n", (char*)hashmap_get(map,str1));
    printf("Get str2:%s\n", (char*)hashmap_get(map,str2));
    printf("Get str3:%s\n", (char*)hashmap_get(map,str3));
    printf("Get str4:%s\n", (char*)hashmap_get(map,str4));
    printf("Get str5:%s\n", (char*)hashmap_get(map,str5));
    printf("Get str6:%s\n", (char*)hashmap_get(map,str6));

    printf("\n\nRemoving all\n");
    hashmap_del(map,my_str);
    hashmap_del(map,str1);
    hashmap_del(map,str2);
    hashmap_del(map,str3);
    hashmap_del(map,str4);
    hashmap_del(map,str5);
    hashmap_del(map,str6);
    hashmap_print(map);
    hashmap_free(map);
}


void main()
{
//    tests();
    parse_config("ssa.cfg");
    free_config();
}
