// Copyright 2025 Block, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package starttls

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"

	"github.com/mwitkow/go-http-dialer"
)

// Dialer is an interface for dialers (either net.Dialer, or http_dialer.HttpTunnel)
type Dialer interface {
	Dial(network, address string) (net.Conn, error)
}

// bufferedConn feeds bytes that a buffered reader over-read during the
// plaintext phase of a STARTTLS exchange into the TLS layer after the
// protocol upgrade. Without it, data sitting in a bufio.Reader buffer would
// be lost the moment the connection is wrapped with tls.Client.
type bufferedConn struct {
	reader io.Reader
	net.Conn
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// startTLSFunc drives the plaintext part of a STARTTLS exchange on an already
// dialed connection and returns the negotiated TLS connection state. Every
// implementation MUST either complete the TLS handshake or return an error,
// leaving connection cleanup to the caller (dialAndUpgrade).
type startTLSFunc func(conn net.Conn, config *tls.Config) (*tls.ConnectionState, error)

// newNetDialer creates a dialer whose TCP establishment, like every later
// phase of the connection, is bounded by deadline.
func newNetDialer(timeout time.Duration, deadline time.Time) *net.Dialer {
	return &net.Dialer{
		Timeout:  timeout,
		Deadline: deadline,
	}
}

// dialWithDeadline establishes a connection through d (which may tunnel the
// connection through an HTTP CONNECT proxy) and applies the shared deadline
// to everything received or sent afterwards. On failure the half-open
// connection is closed so it can be reclaimed immediately.
func dialWithDeadline(d Dialer, network, addr string, deadline time.Time) (net.Conn, error) {
	conn, err := d.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	if !deadline.IsZero() {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

// dialAndUpgrade runs the whole lifecycle of a certificate probe against a
// single, shared timeout budget: dialing (optionally through a proxy CONNECT
// tunnel), the plaintext STARTTLS exchange and the TLS handshake. The TLS
// connection state is only a snapshot, so the connection is always closed and
// recycled before this function returns, including on every error path.
//
// When upgrade is nil, a direct TLS connection is established.
func dialAndUpgrade(d Dialer, network, addr string, config *tls.Config, deadline time.Time, upgrade startTLSFunc) (*tls.ConnectionState, error) {
	rawConn, err := dialWithDeadline(d, network, addr, deadline)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rawConn.Close()
	}()

	if upgrade != nil {
		state, err := upgrade(rawConn, config)
		if err != nil {
			return nil, err
		}
		return state, nil
	}

	tlsConn := tls.Client(rawConn, config)
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	state := tlsConn.ConnectionState()
	return &state, nil
}

// pqDialerAdapter makes the package-level Dialer satisfy the Dialer interface
// expected by the postgres driver (which additionally asks for DialTimeout).
// Both methods route through the same, possibly proxying, dialer and apply the
// shared deadline.
type pqDialerAdapter struct {
	dialer   Dialer
	deadline time.Time
}

func (p pqDialerAdapter) Dial(network, address string) (net.Conn, error) {
	return dialWithDeadline(p.dialer, network, address, p.deadline)
}

func (p pqDialerAdapter) DialTimeout(network, address string, _ time.Duration) (net.Conn, error) {
	return dialWithDeadline(p.dialer, network, address, p.deadline)
}

func wrapDialerWithProxy(dialer *net.Dialer, connectProxy *url.URL, tlsConfig *tls.Config) (Dialer, error) {
	dialerOpt := http_dialer.WithDialer(dialer)
	tlsOpt := http_dialer.WithTls(tlsConfig)
	if connectProxy.User != nil {
		password, ok := connectProxy.User.Password()
		if !ok {
			return nil, fmt.Errorf("proxy username without password not currently supported")
		}
		auth := http_dialer.WithProxyAuth(http_dialer.AuthBasic(connectProxy.User.Username(), password))
		return http_dialer.New(connectProxy, dialerOpt, tlsOpt, auth), nil
	}
	return http_dialer.New(connectProxy, dialerOpt, tlsOpt), nil
}
