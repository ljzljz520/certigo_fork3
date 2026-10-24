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
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	ber "github.com/go-asn1-ber/asn1-ber"
	"io"
	"math/big"
	"net"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Parser-level tests: reply buffering and protocol boundaries
// ---------------------------------------------------------------------------

func TestReadFTPReply(t *testing.T) {
	t.Parallel()

	t.Run("multiline reply from single buffer", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("220-Welcome\r\n220-Line two\r\n220 Ready\r\n234 Proceed\r\n"))
		code, err := readFTPReply(r)
		if err != nil || code != 220 {
			t.Fatalf("got code=%d err=%v, want 220", code, err)
		}
		// The same reader must expose the next reply instead of losing it.
		code, err = readFTPReply(r)
		if err != nil || code != 234 {
			t.Fatalf("got code=%d err=%v, want 234 (buffered continuation lost?)", code, err)
		}
	})

	t.Run("fragmented multiline reply", func(t *testing.T) {
		r := bufio.NewReader(&oneByteReader{data: []byte("220-Welcome\r\n220 Ready\r\n")})
		code, err := readFTPReply(r)
		if err != nil || code != 220 {
			t.Fatalf("got code=%d err=%v, want 220", code, err)
		}
	})

	t.Run("refusal code", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("534 TLS not available\r\n"))
		code, err := readFTPReply(r)
		if err != nil || code != 534 {
			t.Fatalf("got code=%d err=%v, want 534", code, err)
		}
	})

	t.Run("mismatched continuation codes", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("220-Welcome\r\n221 Ready\r\n"))
		if _, err := readFTPReply(r); err == nil {
			t.Fatal("expected protocol error for mismatched codes")
		}
	})
}

func TestReadIMAPCompletion(t *testing.T) {
	t.Parallel()

	t.Run("greeting", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("* OK IMAP4rev1 ready\r\n"))
		status, err := readIMAPCompletion(r, "")
		if err != nil || status != "OK" {
			t.Fatalf("got status=%q err=%v, want OK", status, err)
		}
	})

	t.Run("fragmented greeting", func(t *testing.T) {
		r := bufio.NewReader(&oneByteReader{data: []byte("* OK IMAP4rev1 ready\r\n")})
		status, err := readIMAPCompletion(r, "")
		if err != nil || status != "OK" {
			t.Fatalf("got status=%q err=%v, want OK", status, err)
		}
	})

	t.Run("tagged completion after untagged data and literal", func(t *testing.T) {
		// Untagged response carrying a 5-byte literal, then tagged completion.
		payload := "* 1 FETCH (BODY[] {5}\r\nhello\r\n)\r\n* CAPABILITY IMAP4rev1\r\n1 OK done\r\n"
		r := bufio.NewReader(strings.NewReader(payload))
		status, err := readIMAPCompletion(r, "1")
		if err != nil || status != "OK" {
			t.Fatalf("got status=%q err=%v, want OK", status, err)
		}
	})

	t.Run("refusal", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("1 NO STARTTLS disabled\r\n"))
		status, err := readIMAPCompletion(r, "1")
		if err != nil || status != "NO" {
			t.Fatalf("got status=%q err=%v, want NO", status, err)
		}
	})

	t.Run("tagged line where greeting expected", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("1 OK not a greeting\r\n"))
		if _, err := readIMAPCompletion(r, ""); err == nil {
			t.Fatal("expected protocol error for malformed greeting")
		}
	})
}

type oneByteReader struct {
	data []byte
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	p[0] = r.data[0]
	r.data = r.data[1:]
	return 1, nil
}

// ---------------------------------------------------------------------------
// End-to-end lifecycle tests against local TCP/TLS services
// ---------------------------------------------------------------------------

func TestConnectionLifecycle(t *testing.T) {
	tlsCfg := selfSignedServerConfig(t)

	t.Run("direct_tls_fragmented_server_flight", func(t *testing.T) {
		// A plain TLS server splitting its handshake flight across segments.
		srv := startTCPServer(t, func(c net.Conn) {
			tc := tls.Server(&chunkedWriteConn{c, 64}, tlsCfg)
			_ = tc.Handshake()
			_ = tc.Close()
		})
		defer srv.close()

		state, _, err := GetConnectionState("", "", srv.addr(), "", "", "", nil, 5*time.Second)
		if err != nil {
			t.Fatalf("direct TLS connect: %v", err)
		}
		assertPeerCertificate(t, state)
	})

	t.Run("direct_tls_timeout_recycles_connection", func(t *testing.T) {
		srv := startTCPServer(t, silentHandler)
		defer srv.close()

		start := time.Now()
		_, _, err := GetConnectionState("", "", srv.addr(), "", "", "", nil, 200*time.Millisecond)
		elapsed := time.Since(start)
		assertTimeoutError(t, err)
		if elapsed >= 2*time.Second {
			t.Fatalf("timeout budget not enforced, returned after %v", elapsed)
		}
		// Closing the server waits for the handler: it only returns once the
		// client has closed its side of the socket.
		srv.closeWithTimeout(t, 2*time.Second)
	})

	t.Run("ftp_fragmented_reply", func(t *testing.T) {
		srv := startTCPServer(t, ftpHandler(t, tlsCfg, "ok", nil))
		defer srv.close()

		state, _, err := GetConnectionState("ftp", "", srv.addr(), "", "", "", nil, 5*time.Second)
		if err != nil {
			t.Fatalf("ftp fragmented connect: %v", err)
		}
		assertPeerCertificate(t, state)
	})

	t.Run("ftp_upgrade_refused", func(t *testing.T) {
		closed := make(chan struct{}, 1)
		srv := startTCPServer(t, ftpHandler(t, tlsCfg, "refuse", closed))
		defer srv.close()

		_, _, err := GetConnectionState("ftp", "", srv.addr(), "", "", "", nil, 5*time.Second)
		if err == nil || !strings.Contains(err.Error(), "534") {
			t.Fatalf("err = %v, want refusal mentioning status 534", err)
		}
		assertClientClosed(t, closed)
	})

	t.Run("ftp_timeout", func(t *testing.T) {
		srv := startTCPServer(t, silentHandler)
		defer srv.close()

		start := time.Now()
		_, _, err := GetConnectionState("ftp", "", srv.addr(), "", "", "", nil, 200*time.Millisecond)
		elapsed := time.Since(start)
		assertTimeoutError(t, err)
		if elapsed >= 2*time.Second {
			t.Fatalf("timeout budget not enforced, returned after %v", elapsed)
		}
		srv.closeWithTimeout(t, 2*time.Second)
	})

	t.Run("imap_fragmented_reply", func(t *testing.T) {
		srv := startTCPServer(t, imapHandler(t, tlsCfg, "ok", nil))
		defer srv.close()

		state, _, err := GetConnectionState("imap", "", srv.addr(), "", "", "", nil, 5*time.Second)
		if err != nil {
			t.Fatalf("imap fragmented connect: %v", err)
		}
		assertPeerCertificate(t, state)
	})

	t.Run("imap_upgrade_refused", func(t *testing.T) {
		closed := make(chan struct{}, 1)
		srv := startTCPServer(t, imapHandler(t, tlsCfg, "refuse", closed))
		defer srv.close()

		_, _, err := GetConnectionState("imap", "", srv.addr(), "", "", "", nil, 5*time.Second)
		if err == nil || !strings.Contains(err.Error(), "NO") {
			t.Fatalf("err = %v, want refusal mentioning NO", err)
		}
		assertClientClosed(t, closed)
	})

	t.Run("imap_timeout", func(t *testing.T) {
		srv := startTCPServer(t, silentHandler)
		defer srv.close()

		start := time.Now()
		_, _, err := GetConnectionState("imap", "", srv.addr(), "", "", "", nil, 200*time.Millisecond)
		elapsed := time.Since(start)
		assertTimeoutError(t, err)
		if elapsed >= 2*time.Second {
			t.Fatalf("timeout budget not enforced, returned after %v", elapsed)
		}
		srv.closeWithTimeout(t, 2*time.Second)
	})

	t.Run("ldap_upgrade", func(t *testing.T) {
		srv := startTCPServer(t, ldapHandler(t, tlsCfg, "ok", nil))
		defer srv.close()

		state, _, err := GetConnectionState("ldap", "", srv.addr(), "", "", "", nil, 5*time.Second)
		if err != nil {
			t.Fatalf("ldap connect: %v", err)
		}
		assertPeerCertificate(t, state)
	})

	t.Run("ldap_upgrade_refused", func(t *testing.T) {
		closed := make(chan struct{}, 1)
		srv := startTCPServer(t, ldapHandler(t, tlsCfg, "refuse", closed))
		defer srv.close()

		_, _, err := GetConnectionState("ldap", "", srv.addr(), "", "", "", nil, 5*time.Second)
		if err == nil {
			t.Fatal("expected StartTLS refusal error")
		}
		assertClientClosed(t, closed)
	})

	t.Run("ldap_timeout_reaps_goroutines", func(t *testing.T) {
		srv := startTCPServer(t, silentHandler)
		defer srv.close()

		start := time.Now()
		_, _, err := GetConnectionState("ldap", "", srv.addr(), "", "", "", nil, 200*time.Millisecond)
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("expected a timeout error, got nil")
		}
		if elapsed >= 2*time.Second {
			t.Fatalf("timeout budget not enforced, returned after %v", elapsed)
		}
		// Server-side reaping proves the underlying socket was closed; the
		// final leak scan proves ldap's reader/writer goroutines exited.
		srv.closeWithTimeout(t, 2*time.Second)
	})

	t.Run("smtp_fragmented_reply", func(t *testing.T) {
		srv := startTCPServer(t, smtpHandler(t, tlsCfg, "ok", nil))
		defer srv.close()

		state, _, err := GetConnectionState("smtp", "", srv.addr(), "test.local", "", "", nil, 5*time.Second)
		if err != nil {
			t.Fatalf("smtp fragmented connect: %v", err)
		}
		assertPeerCertificate(t, state)
	})

	t.Run("smtp_upgrade_refused", func(t *testing.T) {
		closed := make(chan struct{}, 1)
		srv := startTCPServer(t, smtpHandler(t, tlsCfg, "refuse", closed))
		defer srv.close()

		_, _, err := GetConnectionState("smtp", "", srv.addr(), "test.local", "", "", nil, 5*time.Second)
		if err == nil {
			t.Fatal("expected STARTTLS refusal error")
		}
		assertClientClosed(t, closed)
	})

	t.Run("unknown_protocol", func(t *testing.T) {
		if _, _, err := GetConnectionState("nntp", "", "127.0.0.1:1", "", "", "", nil, time.Second); err == nil {
			t.Fatal("expected unknown protocol error")
		}
	})

	t.Run("mysql_fragmented_handshake", func(t *testing.T) {
		srv := startTCPServer(t, mysqlHandler(t, tlsCfg, "ok", nil))
		defer srv.close()

		state, _, err := GetConnectionState("mysql", "", srv.addr(), "", "", "", nil, 5*time.Second)
		if err != nil {
			t.Fatalf("mysql connect: %v", err)
		}
		assertPeerCertificate(t, state)
	})

	t.Run("mysql_tls_not_advertised", func(t *testing.T) {
		closed := make(chan struct{}, 1)
		srv := startTCPServer(t, mysqlHandler(t, tlsCfg, "refuse", closed))
		defer srv.close()

		_, _, err := GetConnectionState("mysql", "", srv.addr(), "", "", "", nil, 5*time.Second)
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "tls") {
			t.Fatalf("err = %v, want error about TLS not being enabled", err)
		}
		assertClientClosed(t, closed)
	})

	t.Run("mysql_via_proxy", func(t *testing.T) {
		target := startTCPServer(t, mysqlHandler(t, tlsCfg, "ok", nil))
		defer target.close()
		proxy := startConnectProxy(t)
		defer proxy.close()

		state, _, err := GetConnectionState("mysql", "", target.addr(), "", "", "", proxy.url(), 5*time.Second)
		if err != nil {
			t.Fatalf("mysql via proxy: %v", err)
		}
		assertPeerCertificate(t, state)
		if !proxy.sawTarget(target.addr()) {
			t.Fatal("mysql traffic did not go through the proxy")
		}
	})

	t.Run("mysql_timeout", func(t *testing.T) {
		srv := startTCPServer(t, silentHandler)
		defer srv.close()

		start := time.Now()
		_, _, err := GetConnectionState("mysql", "", srv.addr(), "", "", "", nil, 200*time.Millisecond)
		elapsed := time.Since(start)
		assertTimeoutError(t, err)
		if elapsed >= 2*time.Second {
			t.Fatalf("timeout budget not enforced, returned after %v", elapsed)
		}
		srv.closeWithTimeout(t, 2*time.Second)
	})

	t.Run("postgres_fragmented_handshake", func(t *testing.T) {
		srv := startTCPServer(t, postgresHandler(t, tlsCfg, "ok", nil))
		defer srv.close()

		state, _, err := GetConnectionState("postgres", "", srv.addr(), "", "", "", nil, 5*time.Second)
		if err != nil {
			t.Fatalf("postgres connect: %v", err)
		}
		assertPeerCertificate(t, state)
	})

	t.Run("postgres_tls_refused", func(t *testing.T) {
		closed := make(chan struct{}, 1)
		srv := startTCPServer(t, postgresHandler(t, tlsCfg, "refuse", closed))
		defer srv.close()

		_, _, err := GetConnectionState("postgres", "", srv.addr(), "", "", "", nil, 5*time.Second)
		if err == nil {
			t.Fatal("expected error when server rejects the SSLRequest")
		}
		assertClientClosed(t, closed)
	})

	t.Run("postgres_via_proxy", func(t *testing.T) {
		target := startTCPServer(t, postgresHandler(t, tlsCfg, "ok", nil))
		defer target.close()
		proxy := startConnectProxy(t)
		defer proxy.close()

		state, _, err := GetConnectionState("postgres", "", target.addr(), "", "", "", proxy.url(), 5*time.Second)
		if err != nil {
			t.Fatalf("postgres via proxy: %v", err)
		}
		assertPeerCertificate(t, state)
		if !proxy.sawTarget(target.addr()) {
			t.Fatal("postgres traffic did not go through the proxy")
		}
	})

	t.Run("postgres_timeout", func(t *testing.T) {
		srv := startTCPServer(t, silentHandler)
		defer srv.close()

		start := time.Now()
		_, _, err := GetConnectionState("postgres", "", srv.addr(), "", "", "", nil, 200*time.Millisecond)
		elapsed := time.Since(start)
		assertTimeoutError(t, err)
		if elapsed >= 2*time.Second {
			t.Fatalf("timeout budget not enforced, returned after %v", elapsed)
		}
		srv.closeWithTimeout(t, 2*time.Second)
	})

	// All traffic, including the plaintext upgrade, must travel through the
	// configured CONNECT proxy.
	t.Run("direct_tls_via_proxy", func(t *testing.T) {
		target := startTCPServer(t, func(c net.Conn) {
			tc := tls.Server(c, tlsCfg)
			_ = tc.Handshake()
			_ = tc.Close()
		})
		defer target.close()
		proxy := startConnectProxy(t)
		defer proxy.close()

		state, _, err := GetConnectionState("", "", target.addr(), "", "", "", proxy.url(), 5*time.Second)
		if err != nil {
			t.Fatalf("TLS via proxy: %v", err)
		}
		assertPeerCertificate(t, state)
		if !proxy.sawTarget(target.addr()) {
			t.Fatal("proxy never received CONNECT for the target")
		}
	})

	t.Run("ftp_fragmented_via_proxy", func(t *testing.T) {
		target := startTCPServer(t, ftpHandler(t, tlsCfg, "ok", nil))
		defer target.close()
		proxy := startConnectProxy(t)
		defer proxy.close()

		state, _, err := GetConnectionState("ftp", "", target.addr(), "", "", "", proxy.url(), 5*time.Second)
		if err != nil {
			t.Fatalf("ftp via proxy: %v", err)
		}
		assertPeerCertificate(t, state)
		if !proxy.sawTarget(target.addr()) {
			t.Fatal("proxy never received CONNECT for the FTP target")
		}
	})

	t.Run("ftp_refused_via_proxy_closes_tunnel", func(t *testing.T) {
		closed := make(chan struct{}, 1)
		target := startTCPServer(t, ftpHandler(t, tlsCfg, "refuse", closed))
		defer target.close()
		proxy := startConnectProxy(t)
		defer proxy.close()

		_, _, err := GetConnectionState("ftp", "", target.addr(), "", "", "", proxy.url(), 5*time.Second)
		if err == nil || !strings.Contains(err.Error(), "534") {
			t.Fatalf("err = %v, want refusal mentioning status 534", err)
		}
		assertClientClosed(t, closed)
		if !proxy.sawTarget(target.addr()) {
			t.Fatal("refusal was handled without going through the proxy")
		}
	})

	// Every timed-out or refused attempt above must have unwound fully.
	t.Run("no_goroutine_leaks", func(t *testing.T) {
		assertNoGoroutineLeaks(t)
	})
}

// ---------------------------------------------------------------------------
// Local test services
// ---------------------------------------------------------------------------

type tcpServer struct {
	t        *testing.T
	listener net.Listener
	wg       sync.WaitGroup
}

func startTCPServer(t *testing.T, handle func(net.Conn)) *tcpServer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &tcpServer{t: t, listener: l}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func(c net.Conn) {
				defer s.wg.Done()
				defer c.Close()
				if tc, ok := c.(*net.TCPConn); ok {
					_ = tc.SetNoDelay(true)
				}
				handle(c)
			}(c)
		}
	}()
	return s
}

func (s *tcpServer) addr() string {
	return s.listener.Addr().String()
}

func (s *tcpServer) close() {
	_ = s.listener.Close()
	s.wg.Wait()
}

// closeWithTimeout asserts that all in-flight handlers (blocked on reading
// from the probe connection) unwind, i.e. the client recycled its socket.
func (s *tcpServer) closeWithTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	_ = s.listener.Close()
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("probe connection was not closed within %v", d)
	}
}

// silentHandler accepts and consumes data until the peer closes. Used for
// timeout scenarios where no protocol reply ever arrives.
func silentHandler(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.Copy(io.Discard, c)
}

// writeStaggered sends data in tiny chunks so replies are spread across TCP
// segments and the client cannot rely on a single Read returning the record.
func writeStaggered(w io.Writer, data string, pause time.Duration) {
	b := []byte(data)
	for i := 0; i < len(b); i += 2 {
		end := i + 2
		if end > len(b) {
			end = len(b)
		}
		if _, err := w.Write(b[i:end]); err != nil {
			return
		}
		if pause > 0 {
			time.Sleep(pause)
		}
	}
}

// chunkedWriteConn forces server-side writes through in small records so a
// TLS handshake arrives fragmented across many TCP segments.
type chunkedWriteConn struct {
	net.Conn
	chunkSize int
}

func (c *chunkedWriteConn) Write(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		end := written + c.chunkSize
		if end > len(p) {
			end = len(p)
		}
		n, err := c.Conn.Write(p[written:end])
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

func drainUntilClosed(c net.Conn, closed chan<- struct{}) {
	_, _ = io.Copy(io.Discard, c)
	select {
	case closed <- struct{}{}:
	default:
	}
}

func ftpHandler(t *testing.T, tlsCfg *tls.Config, mode string, clientClosed chan<- struct{}) func(net.Conn) {
	return func(c net.Conn) {
		br := bufio.NewReader(c)
		writeStaggered(c, "220-Welcome to test FTP\r\n220 Ready\r\n", time.Millisecond)

		cmd, err := br.ReadString('\n')
		if err != nil || !strings.HasPrefix(cmd, "AUTH TLS") {
			t.Errorf("ftp: got %q, want AUTH TLS", cmd)
			return
		}

		if mode == "refuse" {
			if _, err := io.WriteString(c, "534 TLS not available\r\n"); err != nil {
				return
			}
			drainUntilClosed(c, clientClosed)
			return
		}

		writeStaggered(c, "234 Proceed with negotiation\r\n", time.Millisecond)
		tc := tls.Server(c, tlsCfg)
		_ = tc.Handshake()
		_ = tc.Close()
	}
}

func imapHandler(t *testing.T, tlsCfg *tls.Config, mode string, clientClosed chan<- struct{}) func(net.Conn) {
	return func(c net.Conn) {
		br := bufio.NewReader(c)
		writeStaggered(c, "* OK IMAP4rev1 test server ready\r\n", time.Millisecond)

		cmd, err := br.ReadString('\n')
		if err != nil || !strings.HasPrefix(cmd, imapStartTLSCommand) {
			t.Errorf("imap: got %q, want %s", cmd, imapStartTLSCommand)
			return
		}

		if mode == "refuse" {
			if _, err := io.WriteString(c, "1 NO STARTTLS disabled\r\n"); err != nil {
				return
			}
			drainUntilClosed(c, clientClosed)
			return
		}

		// Untagged data preceding the tagged completion exercises the
		// protocol-boundary handling.
		if _, err := io.WriteString(c, "* CAPABILITY IMAP4rev1 STARTTLS\r\n"); err != nil {
			return
		}
		writeStaggered(c, "1 OK Begin TLS now\r\n", time.Millisecond)
		tc := tls.Server(c, tlsCfg)
		_ = tc.Handshake()
		_ = tc.Close()
	}
}

func smtpHandler(t *testing.T, tlsCfg *tls.Config, mode string, clientClosed chan<- struct{}) func(net.Conn) {
	return func(c net.Conn) {
		br := bufio.NewReader(c)
		writeStaggered(c, "220 test ESMTP ready\r\n", time.Millisecond)

		ehlo, err := br.ReadString('\n')
		if err != nil || (!strings.HasPrefix(ehlo, "EHLO") && !strings.HasPrefix(ehlo, "HELO")) {
			t.Errorf("smtp: got %q, want EHLO", ehlo)
			return
		}
		if _, err := io.WriteString(c, "250-local greets you\r\n250-STARTTLS\r\n250 OK\r\n"); err != nil {
			return
		}

		cmd, err := br.ReadString('\n')
		if err != nil || !strings.HasPrefix(cmd, "STARTTLS") {
			t.Errorf("smtp: got %q, want STARTTLS", cmd)
			return
		}

		if mode == "refuse" {
			if _, err := io.WriteString(c, "502 5.5.1 STARTTLS not available\r\n"); err != nil {
				return
			}
			drainUntilClosed(c, clientClosed)
			return
		}

		writeStaggered(c, "220 2.0.0 Go ahead\r\n", time.Millisecond)
		tc := tls.Server(c, tlsCfg)
		if err := tc.Handshake(); err != nil {
			t.Logf("smtp tls handshake: %v", err)
			return
		}
		// net/smtp re-runs EHLO after STARTTLS completes.
		tlsReader := bufio.NewReader(tc)
		postEHLO, err := tlsReader.ReadString('\n')
		if err != nil || !strings.HasPrefix(postEHLO, "EHLO") {
			t.Errorf("smtp: got %q over TLS, want EHLO (err=%v)", postEHLO, err)
			return
		}
		if _, err := io.WriteString(tc, "250-local greets you\r\n250 AUTH PLAIN\r\n"); err != nil {
			return
		}
		// Wait for the client to capture state and close the connection.
		_ = tc.SetReadDeadline(time.Now().Add(time.Second))
		_, _ = tlsReader.ReadString('\n')
		_ = tc.Close()
	}
}

// Minimal MySQL server speaking just enough of the handshake phase:
// HandshakeV10, then the client's SSL request, then TLS.
func mysqlHandler(t *testing.T, tlsCfg *tls.Config, mode string, clientClosed chan<- struct{}) func(net.Conn) {
	const (
		clientProtocol41 = 1 << 9
		clientSSL        = 1 << 11
		clientSecureConn = 1 << 15
	)
	return func(c net.Conn) {
		var payload bytes.Buffer
		payload.WriteByte(10)             // protocol version 10
		payload.WriteString("5.7.0-test") // server version
		payload.WriteByte(0)
		_ = binary.Write(&payload, binary.LittleEndian, uint32(1)) // connection id
		payload.WriteString("12345678")                            // auth-plugin-data part 1
		payload.WriteByte(0)                                       // filler

		caps := uint16(clientProtocol41 | clientSecureConn)
		if mode != "refuse" {
			caps |= clientSSL
		}
		_ = binary.Write(&payload, binary.LittleEndian, caps)
		payload.WriteByte(33)                                      // character set
		_ = binary.Write(&payload, binary.LittleEndian, uint16(2)) // status flags
		_ = binary.Write(&payload, binary.LittleEndian, uint16(0)) // capability flags upper
		payload.WriteByte(21)                                      // auth-plugin-data length
		payload.Write(make([]byte, 10))                            // reserved
		payload.WriteString("123456789012")                        // auth-plugin-data part 2

		// Fragment the greeting (length header included) across segments.
		out := &chunkedWriteConn{Conn: c, chunkSize: 16}
		if err := writeMySQLPacket(out, 0, payload.Bytes()); err != nil {
			t.Logf("mysql greeting: %v", err)
			return
		}

		// Read the SSL request packet (32-byte payload + 4-byte header).
		var hdr [4]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			if mode == "refuse" {
				// Driver aborts with ErrNoTLS and closes before sending anything.
				drainSignal(c, clientClosed)
				return
			}
			t.Logf("mysql reading SSL request header: %v", err)
			return
		}
		n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
		if _, err := io.ReadFull(c, make([]byte, n)); err != nil {
			t.Logf("mysql reading SSL request body: %v", err)
			return
		}

		tc := tls.Server(c, tlsCfg)
		if err := tc.Handshake(); err != nil {
			t.Logf("mysql tls handshake: %v", err)
			return
		}
		_ = tc.Close()
	}
}

func writeMySQLPacket(w io.Writer, seq byte, payload []byte) error {
	hdr := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), seq}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// Minimal PostgreSQL frontend/backend SSL negotiation: read the 8-byte SSL
// request, answer S/N, then TLS.
func postgresHandler(t *testing.T, tlsCfg *tls.Config, mode string, clientClosed chan<- struct{}) func(net.Conn) {
	const sslRequestCode = 80877103
	return func(c net.Conn) {
		var msg [8]byte
		if _, err := io.ReadFull(c, msg[:]); err != nil {
			t.Logf("postgres reading SSL request: %v", err)
			return
		}
		length := binary.BigEndian.Uint32(msg[:4])
		code := binary.BigEndian.Uint32(msg[4:])
		if length != 8 || code != sslRequestCode {
			t.Errorf("postgres: got length=%d code=%d, want 8/%d", length, code, sslRequestCode)
			return
		}

		if mode == "refuse" {
			if _, err := c.Write([]byte{'N'}); err != nil {
				return
			}
			drainSignal(c, clientClosed)
			return
		}

		if _, err := c.Write([]byte{'S'}); err != nil {
			return
		}
		tc := tls.Server(c, tlsCfg)
		if err := tc.Handshake(); err != nil {
			t.Logf("postgres tls handshake: %v", err)
			return
		}
		_ = tc.Close()
	}
}

func drainSignal(c net.Conn, closed chan<- struct{}) {
	_, _ = io.Copy(io.Discard, c)
	if closed != nil {
		select {
		case closed <- struct{}{}:
		default:
		}
	}
}

// Minimal LDAP server: consumes the StartTLS extended request, replies with an
// extended response, then speaks TLS just for that connection.
func ldapHandler(t *testing.T, tlsCfg *tls.Config, mode string, clientClosed chan<- struct{}) func(net.Conn) {
	// LDAP result codes.
	const (
		success            = 0
		unwillingToPerform = 53
	)
	return func(c net.Conn) {
		r := bufio.NewReader(c)
		if err := readLDAPMessage(r); err != nil {
			t.Logf("ldap reading StartTLS request: %v", err)
			return
		}

		resultCode := success
		if mode == "refuse" {
			resultCode = unwillingToPerform
		}

		response := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(24), nil, "Extended Response")
		response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(resultCode), "resultCode"))
		response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
		response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "test server", "diagnosticMessage"))

		message := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
		message.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(1), "MessageID"))
		message.AppendChild(response)
		if _, err := c.Write(message.Bytes()); err != nil {
			if mode == "refuse" {
				drainSignal(c, clientClosed)
				return
			}
			t.Logf("ldap writing extended response: %v", err)
			return
		}

		if mode == "refuse" {
			drainSignal(c, clientClosed)
			return
		}

		tc := tls.Server(c, tlsCfg)
		if err := tc.Handshake(); err != nil {
			t.Logf("ldap tls handshake: %v", err)
			return
		}
		// The client closes (Unbind) as soon as the state is captured.
		_ = tc.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.Copy(io.Discard, tc)
		_ = tc.Close()
	}
}

// readLDAPMessage discards one complete BER-encoded LDAP message from r.
func readLDAPMessage(r *bufio.Reader) error {
	// Identifier octets: the envelope is a SEQUENCE (short form 0x30), but
	// handle high-tag-number forms defensively.
	if _, err := r.ReadByte(); err != nil {
		return err
	}
	for {
		b, err := r.ReadByte()
		if err != nil {
			return err
		}
		if b&0x1f != 0x1f {
			return readBERValue(r, b)
		}
	}
}

func readBERValue(r *bufio.Reader, firstLenByte byte) error {
	n := int(firstLenByte)
	if firstLenByte&0x80 != 0 {
		n = 0
		for i := 0; i < int(firstLenByte&0x7f); i++ {
			b, err := r.ReadByte()
			if err != nil {
				return err
			}
			n = n<<8 | int(b)
		}
	}
	_, err := io.CopyN(io.Discard, r, int64(n))
	return err
}

// Minimal HTTP CONNECT proxy: it records every target so tests can prove the
// dialer was used.
type connectProxy struct {
	t        *testing.T
	listener net.Listener
	wg       sync.WaitGroup

	mu      sync.Mutex
	targets []string
}

func startConnectProxy(t *testing.T) *connectProxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	p := &connectProxy{t: t, listener: l}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			p.wg.Add(1)
			go func(c net.Conn) {
				defer p.wg.Done()
				defer c.Close()
				p.serve(c)
			}(c)
		}
	}()
	return p
}

func (p *connectProxy) serve(c net.Conn) {
	br := bufio.NewReader(c)
	requestLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	fields := strings.Fields(requestLine)
	if len(fields) < 2 || fields[0] != "CONNECT" {
		_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}
	target := fields[1]
	for {
		header, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if strings.TrimRight(header, "\r\n") == "" {
			break
		}
	}

	upstream, err := net.Dial("tcp", target)
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer upstream.Close()

	p.mu.Lock()
	p.targets = append(p.targets, target)
	p.mu.Unlock()

	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, upstream); done <- struct{}{} }()
	<-done
}

func (p *connectProxy) url() *url.URL {
	u, err := url.Parse(fmt.Sprintf("http://%s", p.listener.Addr().String()))
	if err != nil {
		p.t.Fatal(err)
	}
	return u
}

func (p *connectProxy) sawTarget(addr string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, target := range p.targets {
		if target == addr {
			return true
		}
	}
	return false
}

func (p *connectProxy) close() {
	_ = p.listener.Close()
	p.wg.Wait()
}

// ---------------------------------------------------------------------------
// Cert generation and assertions
// ---------------------------------------------------------------------------

func selfSignedServerConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
}

func assertPeerCertificate(t *testing.T, state *tls.ConnectionState) {
	t.Helper()
	if state == nil || len(state.PeerCertificates) != 1 {
		t.Fatalf("expected exactly one peer certificate, got %v", state)
	}
	if state.Version < tls.VersionTLS12 {
		t.Fatalf("negotiated TLS version %#x is below TLS 1.2", state.Version)
	}
}

func assertTimeoutError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("error %q is not classified as a timeout", err.Error())
	}
}

func assertClientClosed(t *testing.T, closed <-chan struct{}) {
	t.Helper()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not observe connection close after the failed upgrade")
	}
}

// assertNoGoroutineLeaks polls stack traces for remnants of the connection
// machinery. A deadline-driven lifecycle must leave no goroutines behind
// after timeouts and refused upgrades (the previous watchdog/worker design
// leaked one goroutine per timed-out attempt).
func assertNoGoroutineLeaks(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if leaked := leakedConnectionGoroutines(); len(leaked) == 0 {
			return
		} else if time.Now().After(deadline) {
			t.Fatalf("leaked %d connection goroutine(s):\n%s", len(leaked), strings.Join(leaked, "\n---\n"))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func leakedConnectionGoroutines() []string {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	var leaked []string
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		if strings.Contains(g, "assertNoGoroutineLeaks") || strings.Contains(g, "leakedConnectionGoroutines") {
			continue // this inspection goroutine
		}
		// Testing's own subtest runner naturally sits inside starttls test
		// frames; leaked production workers never carry testing frames.
		if strings.Contains(g, "testing.tRunner") || strings.Contains(g, "testing.(*T).Run") {
			continue
		}
		if strings.Contains(g, "square/certigo/starttls") ||
			strings.Contains(g, "mwitkow/go-http-dialer") ||
			strings.Contains(g, "go-ldap/ldap") {
			leaked = append(leaked, g)
		}
	}
	return leaked
}
