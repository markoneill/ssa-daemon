#include "config.h"
#include "log.h"
#include "hashmap_str.h"
#include <libconfig.h>
#include <string.h>
#define STR_MATCH(s, n) strcmp(s, n) == 0
#define HASHMAP_SIZE 20

char DEFAULT_CONF[] = "default";
hsmap_t* global_config = NULL;
size_t global_config_size = 0;


void add_setting(ssa_config_t* config, config_setting_t* cur_setting) {
	int i;
	const char* value;
	int extension_count = 0;
	const char* name = config_setting_name(cur_setting);

	if (STR_MATCH(name, "Application")) {
		config->profile = strdup(config_setting_get_string(cur_setting));
	}
	else if (STR_MATCH(name, "MinProtocol")) {
		value = config_setting_get_string(cur_setting);
		if (STR_MATCH(value, "1.2")) {
			config->min_version = TLS1_2_VERSION;
		}
		else if (STR_MATCH(value, "1.1")) {
			config->min_version = TLS1_1_VERSION;
		}
		else if (STR_MATCH(value, "1.0")) {
			config->min_version = TLS1_VERSION;
		}
		else {
			log_printf(LOG_ERROR, "Unsupported MinVersion: %s\n", value);
			exit(EXIT_FAILURE);
		}
	}
	else if (STR_MATCH(name, "CipherSuite")) {
		if (config->cipher_list != NULL)
			free(config->cipher_list);
		config->cipher_list = strdup(config_setting_get_string(cur_setting));
	}
	else if (STR_MATCH(name, "SessionCacheTimeout")) {
		config->cache_timeout = config_setting_get_int(cur_setting);
	}
	else if (STR_MATCH(name, "SessionCacheLocation")) {
		if (config->cache_path != NULL)
			free(config->cache_path);
		config->cache_path = strdup(config_setting_get_string(cur_setting));
	}
	else if (STR_MATCH(name, "Validation")) {
		value = config_setting_get_string(cur_setting);
		if (STR_MATCH(value, "Normal")) {
			config->validate = Normal;
		}
		else {
			config->validate = TrustBase;
		}
	}
	else if (STR_MATCH(name, "TrustStoreLocation")) {
		if (config->trust_store != NULL)
			free(config->trust_store);
		config->trust_store = strdup(config_setting_get_string(cur_setting));
	}
	else if (STR_MATCH(name, "AppCustomValidation")) {
		value = config_setting_get_string(cur_setting);
		config->custom_validation = 0;
		if (STR_MATCH(value, "On")) {
			config->custom_validation = 1;
		}
	}
	else if (STR_MATCH(name, "Extensions")) {
		extension_count = config_setting_length(cur_setting);
		for(i = 0; i < extension_count; i++) {
			const char* extension = config_setting_get_string_elem(cur_setting, i);
			if (STR_MATCH(extension, "SNI")) {
				config->extensions |= SSA_EXT_SNI;
			} 
			else if (STR_MATCH(extension, "ALPN")) {
				config->extensions |= SSA_EXT_ALPN;
			}
			else if (STR_MATCH(extension, "TICKET")) {
				config->extensions |= SSA_EXT_TICKET;
			}
			else {
				log_printf(LOG_ERROR, "Unsupported Extension: %s\n", extension);
			}
		}
	}
	else if (STR_MATCH(name, "RandomSeed")) {
		extension_count = config_setting_length(cur_setting);
		if (extension_count == 2) {
			config->randseed_path = strdup(config_setting_get_string_elem(cur_setting,0));
			config->randseed_size = config_setting_get_int_elem(cur_setting,1);
			if ( (config->randseed_path == NULL) || (config->randseed_size == 0))
			{
				log_printf(LOG_ERROR, "Invalid RandomSeed configuration \n");
			}
		}
		else {
			log_printf(LOG_ERROR, "Invalid RandomSeed configuration\n");
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
	cur->randseed_path     = strdup(def->randseed_path);
	cur->randseed_size     = def->randseed_size;

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
	if (conf->randseed_path != NULL)
		free(conf->randseed_path);
	free(conf);
}

void free_config()
{
	str_hashmap_deep_free(global_config,free_config_entry);
	global_config = NULL;
	global_config_size = 0;
}

size_t parse_config(char* filename) {
	int i;
	int j;
	free_config(); // Just incase you call parse_config multiple times
	config_t cfg;
	config_setting_t *default_profile;
	config_setting_t *cur_profile;
	config_setting_t *cur_setting;
	config_setting_t *profiles;
	ssa_config_t* default_config;
	ssa_config_t* cur_config;

	int num_profiles;

	config_init(&cfg);
	if (!config_read_file(&cfg, filename)) {
		log_printf(LOG_ERROR, "Error loading config file %s: %s %d\n", filename, config_error_text(&cfg), config_error_line(&cfg));
		return -1;
	}
	profiles = config_lookup(&cfg, "Profiles");
	if ( profiles != NULL ) {
		num_profiles = config_setting_length(profiles);
	} else {
		num_profiles = 0;
	}
	// global_config = calloc(num_profiles + 1, sizeof(ssa_config_t));
	global_config = str_hashmap_create(HASHMAP_SIZE);
	default_config = calloc(1,sizeof(ssa_config_t));
	global_config_size = num_profiles + 1;
	
	// Parse default
	default_profile = config_lookup(&cfg, "Default");
	int default_i = config_setting_length(default_profile);
	for (i = 0; i < default_i; i++) {
		add_setting(default_config, config_setting_get_elem(default_profile, i));
	}
	//Default profile does not need a name
	default_config->profile = NULL;
	str_hashmap_add(global_config,DEFAULT_CONF,default_config);


	//TODO failout if a default is not set 
	if (config_lookup(&cfg, "Default.MinProtocol") == NULL) {
		log_printf(LOG_ERROR, "Default configuration for MinProtocol not set.\n");
		exit(EXIT_FAILURE);
	}
	if (config_lookup(&cfg, "Default.CipherSuite") == NULL) {
		log_printf(LOG_ERROR, "Default configuration for CipherSuite not set.\n");
		exit(EXIT_FAILURE);
	}
	if (config_lookup(&cfg, "Default.SessionCacheTimeout") == NULL) {
		log_printf(LOG_ERROR, "Default configuration for SessionCacheTimeout not set.\n");
		exit(EXIT_FAILURE);
	}
	if (config_lookup(&cfg, "Default.Validation") == NULL) {
		log_printf(LOG_ERROR, "Default configuration for Validation not set.\n");
		exit(EXIT_FAILURE);
	}
	if (config_lookup(&cfg, "Default.TrustStoreLocation") == NULL) {
		log_printf(LOG_ERROR, "Default configuration for TrustStoreLocation not set.\n");
		exit(EXIT_FAILURE);
	}   
	if (config_lookup(&cfg, "Default.AppCustomValidation") == NULL) {
		log_printf(LOG_ERROR, "Default configuration for AppCustomValidation not set.\n");
		exit(EXIT_FAILURE);
	}
	// Parse all the profiles

	for(i = 0; i < num_profiles; i++) {
		cur_config = malloc(sizeof(ssa_config_t));
		init_ssa_config(default_config, cur_config);
		cur_profile = config_setting_get_elem(profiles, i);
		int num_custom = config_setting_length(cur_profile);
		for (j = 0; j < num_custom; j++) {
			cur_setting = config_setting_get_elem(cur_profile, j);
			add_setting(cur_config, cur_setting);
		}
		str_hashmap_add(global_config,cur_config->profile,cur_config);
	}
	config_destroy(&cfg);
	return global_config_size;
}

/* return NULL if the config has not been parsed 
 * If it has, get the requested application
 * If the requested application does not exist return
 * the default configuration
*/
ssa_config_t* get_app_config(char* app_path)
{
	ssa_config_t* config;

	if (global_config == NULL)
		return NULL;

	config = str_hashmap_get(global_config,app_path);

	if (config == NULL) 
		return str_hashmap_get(global_config,DEFAULT_CONF);
	
	return config;
}

ssa_config_t* get_default_config()
{
	return get_app_config(DEFAULT_CONF);
}
