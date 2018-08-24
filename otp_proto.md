# Incoming messages
### Endpoints
    0 - otp request
    1 - validate otp
    2 - CSR without validation
    3 - Nothing

## OTP Request
    8 bits(1 Byte) - for endpoint specifier
    8 bits (1 Byte) - for the length of the phone number string
    X bits - the phone number as a string
    8 bits (1 Byte) - for the length of the email string
    X bits - the email as a string

## OTP Validate Request
    8 bits (1 Byte) - for endpoint specifier
    1 Byte - for length of Access Code
    64 bits (8 Bytes) - Access Code
    48 bits (6 Bytes) - email OTP
    64 bits (8 Bytes) - phone OTP
    16 bits (2 Bytes) - length of public key in bytes (Max 65535)
    X bits - Their public key

## CSR without validation Request
    8 bits(1 Byte) - for endpoint specifier
    16 bits (2 Bytes) - length of public key in bytes (Max 65535)
    X bits - Their public key

# Outgoing messages
## OTP Request Response
    
    1 byte - access code email length
    55 bytes - Access Code email
    1 byte - access code phone length
    55 bytes -access code phone
    

## OTP Validate Response
    Signed Certificate Null Terminated

