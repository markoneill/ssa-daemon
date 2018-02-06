#include "config.h"
#include <libconfig.h>
#include <string.h>
#define MATCH(s, n) strcmp(s, n) == 0

void add_setting(ssa_config_t* config, config_setting_t* cur_setting) {
    const char* name = config_setting_name(cur_setting);
    const char* value;
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
            // TODO unsupported
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
        }
        
    }
}

void init_ssa_config(ssa_config_t def, ssa_config_t* cur) {
    cur->options           = def.options;
    cur->cipher_list       = strdup(def.cipher_list);
    cur->validate          = def.validate;
    cur->trust_store       = strdup(def.trust_store);
    cur->custom_validation = def.custom_validation;
    cur->cache_timeout     = def.cache_timeout;
    cur->cache_path        = strdup(def.cache_path);
    cur->extensions        = def.extensions;
    cur->min_version       = def.min_version;
    cur->max_version       = def.max_version;
}

void free_config() {
    for (int i = 0; i < global_config_size; i++) {
       if (global_config[i].profile != NULL)
           free(global_config[i].profile);
       if (global_config[i].cipher_list != NULL)
           free(global_config[i].cipher_list);
       if (global_config[i].trust_store != NULL)
           free(global_config[i].trust_store);
       if (global_config[i].cache_path != NULL)
           free(global_config[i].cache_path);
    }
    free(global_config);
    global_config = NULL;
    global_config_size = 0;
}

void parse_config(char* filename) {
    free_config();
    config_t cfg;
    config_setting_t *profiles;
    int num_profiles;
    config_setting_t *default_profile;
    config_setting_t *cur_profile;
    config_setting_t *cur_setting;
    const char* str;
    int myint;

    config_init(&cfg);

    if (!config_read_file(&cfg, filename)) {
        // ERROR
        printf("error loading file %s: %s %d\n", filename, config_error_text(&cfg), config_error_line(&cfg));
    }

    profiles = config_lookup(&cfg, "Profiles");
    num_profiles = config_setting_length(profiles);
    
    global_config = calloc(num_profiles + 1, sizeof(ssa_config_t));
    global_config_size = num_profiles + 1;
    
    // Parse default
    default_profile = config_lookup(&cfg, "Default");
    int default_i = config_setting_length(default_profile);
    for (int i = 0; i < default_i; i++) {
        add_setting(&global_config[0], config_setting_get_elem(default_profile, i));
    }
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
        init_ssa_config(global_config[0], &global_config[i+1]);
        cur_profile = config_setting_get_elem(profiles, i);
        int num_custom = config_setting_length(cur_profile);
        for (int j = 0; j < num_custom; j++) {
            cur_setting = config_setting_get_elem(cur_profile, j);
            add_setting(&global_config[i+1], cur_setting);
        }
    }
    config_destroy(&cfg);
}

void main()
{
    parse_config("ssa.cfg");
    free_config();
}
