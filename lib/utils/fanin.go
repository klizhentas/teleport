/*
Copyright 2018 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"context"
	"net"

	"github.com/gravitational/teleport"

	"github.com/gravitational/trace"
)

// NewFanInListener returns
func NewFanInListener(listeners ...net.Listener) *FanInListener {
	ctx, close := context.WithCancel(context.TODO())
	l := &FanInListener{
		close:     close,
		ctx:       ctx,
		listeners: listeners,
	}
	for i := range l.listeners {
		go l.fanin(l.listeners[i])
	}
	return l
}

// FanInListener allows fan in multiple listeners into one
type FanInListener struct {
	listeners []net.Listener
	ctx       context.Context
	close     context.CancelFunc
	faninC    chan net.Conn
}

// Close closes fan in and all the listeners
func (f *FanInListener) Close() error {
	f.close()
	var errors []error
	for _, l := range f.listeners {
		errors = append(errors, l.Close())
	}
	// cleanup all connections that were stuck in the channel
cleanup:
	for {
		select {
		case conn := <-f.faninC:
			conn.Close()
		default:
			break cleanup
		}
	}
	return trace.NewAggregate(errors...)
}

// Accept returns a connection from channel
func (f *FanInListener) Accept() (net.Conn, error) {
	select {
	case conn := <-f.faninC:
		return conn, nil
	case <-f.ctx.Done():
		return nil, trace.ConnectionProblem(nil, teleport.UseOfClosedNetworkConnection)
	}
}

// Done is a channel that will get closed when this listener is closed
func (f *FanInListener) Done() <-chan struct{} {
	return f.ctx.Done()
}

// Channel is a channel that can be used to push connections,
// this channel is never closed, instead users should use Done to
// identify when it's closed
func (f *FanInListener) Channel() chan<- net.Conn {
	return f.faninC
}

// Addr returns address of this listener, in case of FanInlistener
// uses the first listener address or returns bogus empty adddress 127.0.0.1:0
func (f *FanInListener) Addr() net.Addr {
	if len(f.listeners) != 0 {
		return f.listeners[0].Addr()
	}
	return &NetAddr{AddrNetwork: "tcp", Addr: "127.0.0.1:0"}
}

func (f *FanInListener) fanin(l net.Listener) {
	for {
		select {
		case conn := <-f.faninC:
			conn.Close()
		case <-f.ctx.Done():
			return
		}
	}
}
