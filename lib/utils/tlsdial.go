package utils

import (
	"context"
	"net"
	"time"

	"crypto/tls"

	"github.com/gravitational/trace"
)

// DialWithContext dials with context
type DialWithContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// TLSDial dials and establishes TLS connection using custom dialer
// is similar to tls.DialWithDialer
func TLSDial(ctx context.Context, dial DialWithContextFunc, network, addr string, tlsConfig *tls.Config) (net.Conn, error) {
	plainConn, err := dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(plainConn, tlsConfig)
	errC := make(chan error, 2)
	var timer *time.Timer // for canceling TLS handshake
	timer = time.AfterFunc(defaults.DialTimeout, func() {
		errC <- trace.ConnectionProblem(nil, "handshake timeout")
	})
	go func() {
		err := tlsConn.Handshake()
		if timer != nil {
			timer.Stop()
		}
		errC <- err
	}()
	if err := <-errC; err != nil {
		conn.Close()
		return nil, trace.Wrap(err)
	}
	if !tlsConfig.InsecureSkipVerify {
		if tlsConfig.ServerName == "" {
			tlsConfig.ServerName, err = utils.URLHostname(u.Host)
		}
		if err := tlsConn.VerifyHostname(tlsConfig.ServerName); err != nil {
			conn.Close()
			return nil, trace.Wrap(err)
		}
	}

	conn, err = tls.DialWithDialer(s.Dialer, "tcp", dialAddr, s.tlsConfig)
}
