// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sshutils

import (
	"context"
	"errors"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// NewChanConn returns new connection using ssh channel as a base
func NewChanConn(laddr, raddr net.Addr, ch ssh.Channel) *ChanConn {
	ctx, cancel := context.WithCancel(context.TODO())
	return &ChanConn{
		ctx:     ctx,
		cancel:  cancel,
		Channel: ch,
		Laddr:   laddr,
		Raddr:   raddr,
	}
}

// ChanConn fulfills the net.Conn interface without
// the tcpChan having to hold laddr or raddr directly.
type ChanConn struct {
	ssh.Channel
	Laddr, Raddr net.Addr
	ctx          context.Context
	cancel       context.CancelFunc
}

// Close closes underlying channel
func (t *ChanConn) Close() error {
	t.cancel()
	return t.Channel.Close()
}

// Done returns the channel that signals the connection close
func (t *ChanConn) Done() <-chan struct{} {
	return t.ctx.Done()
}

// LocalAddr returns the local network address.
func (t *ChanConn) LocalAddr() net.Addr {
	return t.Laddr
}

// RemoteAddr returns the remote network address.
func (t *ChanConn) RemoteAddr() net.Addr {
	return t.Raddr
}

// SetDeadline sets the read and write deadlines associated
// with the connection.
func (t *ChanConn) SetDeadline(deadline time.Time) error {
	if err := t.SetReadDeadline(deadline); err != nil {
		return err
	}
	return t.SetWriteDeadline(deadline)
}

// SetReadDeadline sets the read deadline.
// A zero value for t means Read will not time out.
// After the deadline, the error from Read will implement net.Error
// with Timeout() == true.
func (t *ChanConn) SetReadDeadline(deadline time.Time) error {
	// for compatibility with previous version,
	// the error message contains "tcpChan"
	return errors.New("sshutils.chanconn: deadline not supported")
}

// SetWriteDeadline exists to satisfy the net.Conn interface
// but is not implemented by this type.  It always returns an error.
func (t *ChanConn) SetWriteDeadline(deadline time.Time) error {
	return errors.New("sshutils.chanconn: deadline not supported")
}
