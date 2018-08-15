# ssa-daemon
Userspace libevent2-based TLS wrapping daemon for use with the Secure Socket API

## Prerequisites
You will need to run `install_packages.sh` to make sure you have all the dependencies that you need to compile the code.
You also need the SSA module installed on your computer.

## Installation
Before installing the ssa-daemon you need to install the SSA kernel module before running `./tls_wrapper`.

To install ssa-daemon you need to run these commands as root
```
  make release
  ./tls_wrapper
```
If you want to have hostname support run `make hostname-support`

## Configuration
Configuration is currently in the process of being integrated into the ssa-daemon eventually you will be able to specify the type of connections that you are willing to create and also choose preferred cipher suites.

## Compatibility 
The ssa-daemon works on fedora 26 and we are working toward having it work on ubuntu

## Future Work
Finishing up the config file options
