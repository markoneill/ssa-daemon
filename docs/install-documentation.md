# Install Documentation
The SSA has two components - a kernel module and a userspace daemon.
Both need to be installed and running to provide TLS as an operating system service.

## Compatibility
The SSA is actively developed on Fedora, but may work for other distributions with a few minor changes. We are in process of working out the bugs for running on Ubuntu, and Ubuntu specific documentation will be added as it becomes available.

## Installing the kernel module

### Prerequisites

Before building the SSA kernel module, you will need to install the relevant kernel headers and development packages for your Linux distribution

For example, on Fedora, run
```
sudo dnf install kernel-devel-`uname -r` kernel-headers-`uname -r`
sudo dnf install elfutils-libelf-devel
```

### Build and Installation
To install the SSA module type these commands into the terminal while in the ssa project folder as root user
```
make
insmod ssa.ko
```

### Removal
To remove the SSA kernel module, shut down the encryption daemon (if running), and then run the following command as a privileged user:
```
rmmod ssa
```

## Installing the daemon

### Prerequisites
The install_packages.sh script currently installs dependencies for Fedora and Ubuntu systems. You may need to modify this script or install some packages manually if you are using a different Linux distribution.

### Building and Running
Note: You must have the SSA kernel module installed before you build and run the SSA userspace daemon.
To install and run the SSA userspace daemon you need to run these commands as root:

```
  ./install_packages.sh
  make
  ./tls_wrapper
```

If you want to also have support for the AF_HOSTNAME address type, run `make hostname-support` instead of `make`.
This feature will be included by default soon.

To build the daemon with compiler optimizations and without debug logging, run `make release` or `make hostname-support-release` instead of `make`.