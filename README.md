# The Secure Socket API (SSA) Userspace Daemon
The SSA is a Linux kernel module that allows programmers to easily create secure TLS connections using the standard POSIX socket API. This allows programmers to focus more on the developement of their apps without having to interface with complicated TLS libraries. The SSA also allows system administrtors and other power users to customize TLS settings for all connections on the machines they manage, according to their own needs.

## Publication
You can read more about the SSA, it's design goals, and features in our [USENIX Security 2018 paper](https://www.usenix.org/conference/usenixsecurity18/presentation/oneill)

# ssa-daemon
Userspace libevent2-based TLS wrapping daemon for use with the SSA

## Prerequisites
The SSA has two components - a [kernel module](https://github.com/markoneill/ssa) and a userspace daemon (this repository).
Both need to be installed and running to provide TLS as an operating system service.
The kernel component has its own README with installation instructions, and you are encouraged to build and install and component first.

The install_packages.sh script currently installs dependencies for Fedora and Ubuntu systems. You may need to modify this script or install some packages manually if you are using a different Linux distribution.

## Compatibility
The SSA is actively developed on Fedora, but may compile and run on other systems with some minor changes.

## Using the SSA
Go to the [User Documentation](docs/user-documentation.md) to see how to use the SSA and examples of the SSA usage. 

For administrators, see [Admin Documentation](docs/admin-documentation.md) to see the different admin options, what they do, and how to properly create a config file.

Formal API specification will continue to be added to this README as well as [owntrust.org](https://owntrust.org) in the very near future. Eager users are encouraged to see our publication (linked above), [docs](docs/), code, or may contact us directly with questions.

## Status
The SSA is currently a research prototype. As such, it should not yet be used in any mission critical environments. However, we are working toward release as a viable tool for the general public.

## Building and Running
You must have the SSA kernel module installed before you build and run the SSA userspace daemon.
To install and run the SSA userspace daemon you need to run these commands as root:

```
  ./install_packages.sh
  make
  ./tls_wrapper
```


If you want to also have support for the AF_HOSTNAME address type, run `make hostname-support` instead of make.
This feature will be included by default soon.

## Configuration
Configuration is currently in the process of being better-integrated into the userspace daemon.
When we finalize the configuration API, it will be specified here and on [owntrust.org](https://owntrust.org).
See our paper (linked above) for a preview of the types of configuration options administrastors will have.

## Contributions and Thanks
Thank you to Eliezer Colon for noting a compilation issue

## Notices
The SSA is still undergoing large changes as we finalize the interface between it TrustBase, and other certificate validation strategies. Some commits may disable certificate validation temporarily while we work out the kinks between using TrustBase for traffic interception and using its API for certificate validation.

The build-client-auth.sh script is for extra functionality that is still very much in flux and should not be used unless you know what you're getting yourself into.
