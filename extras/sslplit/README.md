This is a sslsplit patch that use the SSA for the intercepted connections.

This patch is dependent on in_tls.h so sslsplit must be cloned within tlswrap
Their is also an included dummy cert that you will need to install into your root store so that applications accept our fake certs.

## Getting started
Start from the tlswrap directory
`clone https://github.com/droe/sslsplit && cd sslsplit`
`cp ../extras/sslplit/* .`
`patch -p1 < 0001-SSA-patch.patch`
`sudo su`
`./start.sh`

When your done you need to turn your firewall back on or you will not have internet access.
`firewallOn.sh`
