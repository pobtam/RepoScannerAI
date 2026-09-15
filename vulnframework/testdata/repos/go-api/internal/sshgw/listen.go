package sshgw

import (
	"net"

	"golang.org/x/crypto/ssh"
)

// Listen accepts SSH connections. It calls into golang.org/x/crypto/ssh so that
// reachability analysis reports a symbol-level finding rather than a
// module-level one.
func Listen(addr string) error {
	cfg := &ssh.ServerConfig{NoClientAuth: true}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(reqs)
		for ch := range chans {
			ch.Reject(ssh.UnknownChannelType, "unsupported")
		}
		conn.Close()
	}
}
