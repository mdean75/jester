# Tasks for Jester

## Next steps:
- ~~Read in existing certificate~~
- ~~Extract relevant certificate fields for new CSR~~
- ~~Store extracted fields on a struct~~

## Overview
### Cert manager
- Read cert(s) to renew
- Extract fields from current cert
- Generate CSR
- Send CSR request
- Validate response or handle error
- Post certificate steps

### What is app configuration?
- cli flags
  - path to cert config/details
    - json or other format file
    - path to cert
    - path to key
    - num days to renew
    - post renewal script path
  - key type
  - key length

### Overview
- ~~read cert to renew~~
- ~~generate priv key~~
- ~~generate csr~~
- ~~renew cert (so numerous steps in this)~~
  - ~~use cert to get current cacerts for requesting cert renewal~~
  - ~~send pkcs10 request with cacert and client cert~~
- validate renewed cert
- ~~save new cert and key (just private key or also pub)~~
- handle post renewal

### Project modules
#### Config/app
All things related to configuration
- cli args
- certificate config (json/yaml/toml)

Behaviors:
- load app config (cli args)
- load and register certificate config

Consideration:
- use -c flag to pass app config which contains:
  - server url, logfile, and path to certs to renew (or inlined)
  - if -c not passed then each option needs manually set (server url and path to certs config)


*note: everything is immutable

#### Certificate
Certificate renewal processing

Behaviors:
- load certificate(s) to renew
- renew certificate
  - generate csr
  - make necessary api calls
  - return renewed cert, new private key, and explicit trust anchor
- validate renewed certificate against original certificate

Dependencies:
- certificate configuration/details
  - path to cert to renew
  - path to cabundle
  - path to private key
  - path to save certificate/private key files
  - etc.

*note: Certificate module's work is complete when the certificate renewal request is returned

#### Autorenew
Daemon runs on schedule and renews when time to renew

Behaviors:
- Monitor list of certs to renew (scheduler?)
- build cert renewal and own renewal flow
- handle response from renewal request
  - run validate
  - save files
  - run post renewal script

Dependencies:
- certificate configuration/details (list of certs to monitor)
  - path to cert to renew
  - path to cabundle
  - path to private key
  - path to save certificate/private key files
  - path to post renewal script
  - etc.

#### http/client
Http client for interfacing with est server

Behaviors
- request explicit trust anchor
- request cert renewal
- encode/decode request/response base64
- decode pkcs7 and encode into pem
- make mTLS client using current client cert, private key, and ca bundle
  - build root trust store
  - build tls config
  - extract root ca cert
  - build identity

Dependencies
- server configuration
  - url base config
  - endpoints
  - current cabundle, client cert, and private key
  - request body

#### http/Server?


#### misc
- run autorenewal daemon or oneshot - cli flag
- run server? - cli flag

###### From est
cli flags: 

--certs-config
  json file path to certs to renew

--est-endpoint
  est server api endpoint? no not endpoint, but server url

autorenewal
* renewal check - is it n days before expiry
* save to dir
* post renewal hook
* orchestration

uses http server for manual renewal, still needs to be a managed cert?
then cli option to send the renewal request to the http server??
