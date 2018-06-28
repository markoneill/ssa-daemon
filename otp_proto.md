# Incoming messages
### Endpoints
    00 - otp request
    01 - validate otp
    10 - quick and dirty csr
    11 - Nothing

## OTP Request
    Two bits for endpoint specifier
    16 bits (2 Bytes) - length of message recvd in bytes (Max 65535)

## OTP Validate Request
    64 bits (8 Bytes) - Access Code
    48 bits (6 Bytes) - OTP
    X  bits (x*8 Bytes) - Length of the public key
    Public key

# Outgoing messages
## OTP Request Response
    64 bits (8 Bytes) - Access Code

## OTP Validate Request
    Signed Certificate Null Terminated

