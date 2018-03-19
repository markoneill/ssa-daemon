// +build darwin dragonfly freebsd linux netbsd openbsd solaris windows

package net

import (
	"runtime"
	"syscall"
)

type TLSConn = TCPConn

const (
	// IPPROTO_TLS int = 175 % 255
	IPPROTO_TLS          int = 205
	SO_HOSTNAME          int = 85
	SO_PEER_CERTIFICATE  int = 86
	SO_CERTIFICATE_CHAIN int = 87
	SO_PRIVATE_KEY       int = 88
	SO_ID                int = 89
)

func (c *TLSConn) SetHostname(hostname string) error {
	return c.tls_setSockoptString(hostname, SO_HOSTNAME)
}

func (c *TLSConn) SetCertificateChain(chain string) error {
	return c.tls_setSockoptString(chain, SO_CERTIFICATE_CHAIN)
}

func (c *TLSConn) SetPrivateKey(key string) error {
	return c.tls_setSockoptString(key, SO_PRIVATE_KEY)
}

func (c *TLSConn) tls_setSockoptString(arg string, opt int) error {
	if c.fd.net != "tls" {
		panic("Not a tls socket")
	}

	fd := c.fd.pfd.Sysfd

	err := syscall.SetsockoptString(fd, IPPROTO_TLS, opt, arg)
	runtime.KeepAlive(fd)

	err = wrapSyscallError("setsockopt", err)

	if err != nil {
		return &OpError{Op: "set", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return nil
}

func (c *TLSConn) GetHostname() (string, error) {
	if c.fd.net != "tls" {
		panic("Not a tls socket")
	}

	fd := c.fd.pfd.Sysfd

	ret, err := syscall.GetsockoptHostname(fd, IPPROTO_TLS, SO_HOSTNAME)

	err = wrapSyscallError("getsockopt", err)

	if err != nil {
		return "", &OpError{Op: "get", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return ret, nil
}

func (c *TLSConn) GetPeerCert() (string, error) {
	if c.fd.net != "tls" {
		panic("Not a tls socket")
	}

	fd := c.fd.pfd.Sysfd

	ret, err := syscall.GetsockoptString(fd, IPPROTO_TLS, SO_PEER_CERTIFICATE, 4098)

	err = wrapSyscallError("getsockopt", err)

	if err != nil {
		return "", &OpError{Op: "get", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return ret, nil
}

func (c *TLSConn) GetID() (uint64, error) {
	if c.fd.net != "tls" {
		panic("Not a tls socket")
	}

	fd := c.fd.pfd.Sysfd

	ret, err := syscall.GetsockoptUint64(fd, IPPROTO_TLS, SO_ID)

	err = wrapSyscallError("getsockopt", err)

	if err != nil {
		return 0, &OpError{Op: "get", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return *ret, nil
}
