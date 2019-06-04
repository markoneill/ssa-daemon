
## Setting the Administrator File
The SSA reads a configuration file to set the administrator security settings. By defaults it reads "ssa.cfg" as the configuration file.

If you wish to change the default, change the file in line 105 of main.c to be the .cfg file you wish to read.

## Creating an Config File
The config file must be made in the .cfg format.
See https://hyperrealm.github.io/libconfig/libconfig_manual.html#Configuration-Files
## Administator Settings 
(taken from config.c in ssa-daemon):

You must create a default profile, and then can make application specific profiles. 
- Default - the settings used on default when using any application not listed in a specific profiles
- Profiles - profiles set specificastion deviations from default policy for a given app path

1. Application - the path to the app
2. MinProtocol - the minimum TLS protocol version that can be used. If lower connections are used, then the connection will not go through. We don't allow SSL version because they are all vulnerable anyways.
3. MaxProtocol - the maximum TLS protocol version that can be used. This must be >= to MinProtocol, or else the SSA will not run. If not given, this value defaults to the highest TLS version.
4. CipherSuite - order of preferred cipher suites to use
    - the format follows https://www.openssl.org/docs/man1.0.2/man1/ciphers.html
    - example: ```CipherSuite: "ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:RSA+AESGCM:RSA+AES:!aNULL:!MD5:!DSS"```
5. SessionCacheTimeout - timeout for session caching
6. SessionCacheLocation - path to store session data, for cross-machine sharing
7. Validation - method of certificate validation. 
    - currently only "Normal" and "Trustbase" are allowed
8. TrustStoreLocatation - designates the path to the PEM certificate file containing all trusted root certificates to be used in the SSA
9. AppCustomValidation - determines whether to honor certificates supplied by apps for hard-coded validation
    - either "On" or "Off"
10. Extensions - 
11. RandomSeed - requires two arguments, randseed_path and randseed_size
    - example - ```RandomSeed: {"/dev/random", 512}```

Example cfg file
```
# We must have a default profile
Default = 
{
  # These are comments
  # Protocol sets the Protocol version. 
  # We don't have SSL ones because they're all vulnerable anyway
  MinProtocol: "1.1"

  # CipherSuite is the order of preferred cipher suites to use
  # ! means disabled
  CipherSuite: "ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:RSA+AESGCM:RSA+AES:!aNULL:!MD5:!DSS"

  # Validation is either "TrustBase" or "Normal"
  Validation: "Normal"

  # TrustStoreLocation designates the path to the 
  # PEM certificate file containing all trusted root
  # certificates to be used in the SSA
  # Fadora default
	TrustStoreLocation: "/etc/pki/tls/certs/ca-bundle.crt"
  # Ubuntu default
  # TrustStoreLocation: "/etc/ssl/certs/ca-certificates.crt"

  # AppCustomValidation is either On or Off
  # Determines whether to honor certificates supplied by apps 
  # for hard-coded validation
  AppCustomValidation: "On"

  # Session caching settings
  # Timeout, in seconds
  SessionCacheTimeout: 300
  # Path to store session data, for cross-machine sharing
  SessionCacheLocation: "/ssa/session/"

  # Extensions
  # I need your help with this section. You know what functions we should be calling
  # in OpenSSL and with what params. Make something smart here that will work
  Extensions: ("SNI", "ALPN")

  # Misc
  # Seed location and stuff
  RandomSeed: ("/dev/random", 512)
}

# Profiles set specific deviations from default policy
# for a given app path
Profiles = 
(   {
        Application: "/bin/ncat"
        MinProtocol: "1.2"
        CipherSuite: "ECDH+AESGCM:DH+AESGCM:ECDH+AES256:!aNULL:!MD5:!DSS"
    },
    {
        Application: "/bin/httpd"
        AppCustomValidation: "Off"
    }
)


```
