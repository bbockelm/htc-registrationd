//go:build !unix

package portsplit

import "net"

// peekKind treats every connection as CEDAR where MSG_PEEK is unavailable;
// HTCondor's shared port is not used there.
func peekKind(net.Conn) (Kind, error) { return CEDAR, nil }
