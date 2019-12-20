## Purpose 
This document is for developers who want to contribute to the SSA (if you are a developer hoping to utilize the SSA in your application, see docs/user_docs/user-documentation.md). It is intended to help developers understand the SSA-Daemon codebase and to explain how to make changes to the SSA-Daemon and where those changes should happen.

This README is a WIP and can be changed as needed.

## Overview
### Socket communication with SSA

The following diagram shows non-TLS network communication using POSIX sockets. Processes (through their sockets) communicate directly with other machines over the internet. Sockets are established by making system calls to the kernel (technically, socket communication also involves the kernel, but those details are ommitted from the diagram for simplicity). It is important to note that this diagram also acurately shows TLS network communication using SSA _from the perspective of the application developer._ With SSA, from the point of view of the developer, the only difference between TLS and non-TLS sockets is that TLS sockets transmit encrypted traffic according to the TLS protocol

![Socket communication without SSA](socketsWithoutSSA.png)

The next diagram shows the inner-workings of TLS network communication using SSA. Processes create sockets by making system calls to the kernel. When the kernel sees that a process has requested a TLS socket, it defers behavior to the SSA Kernel Module. 

Instead of setting up a socket with the intended end host, the kernel module instead sets up a socket with the SSA daemon. Then, via a netlink socket, the kernel module instructs the SSA daemon to establish a socket with the process and a corresponding socket with the end host. When setting up the socket with the end host, the daemon performs the TLS handshake with the end host (according to the admin-defined config file) to establish a TLS connection.

When the process sends data through the socket, that data first goes to the SSA daemon, which encrpyts it and then passes it on to the end host. When the end host sends data to the process, that data first goes to the SSA daemon, which decrypts it and then passes it on to the prcoess. The process, however, is unaware that it is communicating through the SSA daemon. It believes that its socket is connected directly to the end host. 

![Socket communication with SSA](socketsWithSSA.png)

### Major libraries
The SSA-Daemon uses three major third-party libraries. The Netlink library (INSERT LINK) is used for communicating with the kernel module. The OpenSSL library (INSERT LINK) is used for handling the TLS connections. The Libevent library (INSERT LINK) is used to manage the event-loop that lies at the heart of the SSA-Daemon.

### Descriptions of files in this repo
**docs** - folder containing documentation for users, admins, developers and testing

**examples** -  folder containing simple example client and server that use SSA

**extras** -  folder containing files for add-on features, most notably addons.c which adds support for the address family AF_HOSTNAME (ADD CROSS REFERENCE)

**qrdisplay** - 

**test_files** - folder containing various files for testing. The .gitignore file ignores all files in this folder 

**config.c/h** - source files for parsing the config files ssa.cfg and ssa.conf

**csr_daemon.c/h** - 

**daemon.c/h** - source files defining the event loop and associated callback functions

**hashmap.c/h** - implementation of a hashmap that maps unsigned longs to void pointers. Used by the daemon to keep track of the sockets it is managing

**hashmap_str.c/h** - implementation of a hashmap that maps strings to void pointers. Used by config.c

**in_tls.h** - file defining constants and structs that should be available to an application using SSA. This is the SSA equivalent of "in.h"

**install_packages.sh** - script for installing dependencies required by the SSA-Daemon

**issue_cert.c/h** - 

**log.c/h** - source files defining SSA-Daemon's logging functionality

**main.c** - source file defining start-up for the SSA-Daemon

**netlink.c/h** - source files defining SSA-Daemon's communication with the SSA kernel module using Netlink

**openssl_compat.c/h** - 

**queue.c/h** - source files defining a queue that does not appear to actually be used by any other files

**self_sign.c/h** - 

**ssa.cfg** - configuration file used by a system administrator to specify standards and settings for TLS connections made by the SSA 

**ssa.conf** - configuration file used by a system administrator to specify standards and settings for TLS connections made by the SSA 

**tb_communications.h** - this file and the tb_connector files (below) provide support for the SSA-Daemon to communicate with the Trustbase application to perform certificate validation (see the trustbase_verify function in tls_wrapper.c).c  Currently, this functionality is not enabled.

**tb_connector.c/h** - see "tb_communications.h"

**tls_wrapper.c/h** - source files defining functions used to manage the TLS connection

## Adding to the SSA Admin Configuration File

To add different options to the administrator configuration file (ssa.cfg or ssa.conf) the following steps need to be followed. 

1. Add the appropiate flag to the ssa_config_t struct found in config.h.
2. Add a case in config.c in the function config.c that captures what the setting name is.
3. Set the appropiate flag based on the parsing in config.c

For example, if I wanted to add a value called foo to the configuration file, and have its value be set to bar, I would have to add the following.
1. In config.c add a ```char* foo ```to the ssa_config_t struct
2. Go to add_setting function in config.c and add an else if (STR_MATCH(name, "foo"))...
3. Set the config->foo value to be whatever value was found (in this case bar)