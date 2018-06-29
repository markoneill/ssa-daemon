# Incoming messages
### Endpoints
    00 - otp request
    01 - validate otp
    10 - CSR without validation
    11 - Nothing

## OTP Request
    8 bits(1 Byte) - for endpoint specifier
    8 bites (1 Byte) - for the length of the phone number string
    X Bits - the phone number as a string

## OTP Validate Request
    64 bits (8 Bytes) - Access Code
    48 bits (6 Bytes) - OTP
    16 bits (2 Bytes) - length of message recvd in bytes (Max 65535)
    X bits - Their public key

## CSR without validation Request
    8 bits(1 Byte) - for endpoint specifier
    16 bits (2 Bytes) - length of message recvd in bytes (Max 65535)
    X bits - Their public key

# Outgoing messages
## OTP Request Response
    64 bits (8 Bytes) - Access Code

## OTP Validate Response
    Signed Certificate Null Terminated

