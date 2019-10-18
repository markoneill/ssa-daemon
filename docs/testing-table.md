| Test Name                                 | Written?  | Description                                                                             | Verified Working?  |
|-------------------------------------------|-----------|-----------------------------------------------------------------------------------------|--------------------|
| Creating Simple-Client (in docs)          | Yes       | A simple test client to ensure proper install                                           | Yes                |
| Creating Simple-Server (in docs)          | Yes       | A simple test server to ensure proper install                                           | Yes                |
| Creating Simple-Client (in repo)          | Yes       | A simple test client to ensure proper install                                           | Yes                |
| Creating Simple-Server (in repo)          | Yes       | A simple test server to ensure proper install                                           | Yes                |
|  MinProtocol                              | Yes       | A test of various versions of TLS to show what version admins can set for MinProtocol   | Yes                |
| MaxProtocol                               | Yes       | A test of various versions of TLS to show what version admins can set  for Max Protocol | Yes                |
| CipherSuite                               | Yes       | Test of various CipherSuites in various orders                                          | NA                 |
| TrustStoreLocation                        | Yes       | Tests setting TrustStoreLocation on various systems                                     |                    |
| AppCustomValidation                       | NO        | ???                                                                                     |                    |
| TLS_REMOTE_HOSTNAME                       | no        |                                                                                         |                    |
| TLS_HOSTNAME                              | no        |                                                                                         |                    |
| TLS_CERTIFICATE_CHAIN and TLS_PRIVATE_KEY | kinda     | Should test validation but validation not currently working                             |                    |
| TLS_TRUSTED_PEER_CERTIFICATES             |           |                                                                                         |                    |
| TLS_ALPN                                  |           |                                                                                         |                    |
| TLS_SESSION_TTL                           |           |                                                                                         |                    |
| TLS_DISABLE_CIPHER                        | yes       | tests that get sockopt fails with disable cipher                                        |                    |
| TLS_PEER_IDENTITY                         | yes       | test that sockopt fails with TLS_PEER_IDENTITY                                          |                    |
| TLS_PEER_CERTIFICATE_CHAIN                | no        |                                                                                         |                    |
| Session Cache Timeout                     | NO        | Test of the functionality of timeout for session cacching                               | NA                 |
| Validation                                | NO        | Test of toggle for "Normal" and "Trustbase" types of validation maybe test alternatives | NA                 |
| RandomSeed                                | NO        | Test of randomness of PRNG of open ssl                                                  |                    |
| TLS_REMOTE_HOSTNAME                       | NO        |                                                                                         |                    |
| TLS_HOSTNAME                              | no        |                                                                                         |                    |
| TLS_CERT_CHAIN and TLS_PRIVATE_KEY        | no        |                                                                                         |                    |
| TLS_TRUSTED_PEER_CERTS                    | no        |                                                                                         |                    |
| TLS_ALPN                                  | no        |                                                                                         |                    |
| TLS_SESSION_TTL                           | no        |                                                                                         |                    |
| TLS_DISABLE_CIPHER                        | no        |                                                                                         |                    |
| TLS_PEER_IDENTITY                         | no        |                                                                                         |                    |
| TLS_PEER_CERT_CHAIN                       | no        |                                                                                         |                    |
|                                           |           |                                                                                         |                    |
