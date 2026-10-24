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
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/square/certigo/starttls/mysql"
	pq "github.com/square/certigo/starttls/psql"
)

// Protocols are the names of supported protocols
var Protocols = []string{"mysql", "postgres", "psql", "smtp", "ldap", "ftp", "imap"}

func tlsConfigForConnect(connectName, connectTo, clientCert, clientKey string) (*tls.Config, **tls.CertificateRequestInfo, error) {
	var hostname string
	if connectName != "" {
		hostname = connectName
	} else {
		hostname = strings.Split(connectTo, ":")[0]
	}

	conf := &tls.Config{
		// We verify later manually so we can print results
		InsecureSkipVerify: true,
		ServerName:         hostname,
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       allSupportedCipherSuiteIDs(),
	}

	var err error
	var cert tls.Certificate

	if clientCert != "" {
		keyFile := clientCert
		if clientKey != "" {
			keyFile = clientKey
		}

		cert, err = tls.LoadX509KeyPair(clientCert, keyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to read client certificate/key: %s", err)
		}

		// Required even if we set fallback, because of bug in Go 1.8.0 (fixed in 1.8.1)
		conf.Certificates = []tls.Certificate{cert}
	}

	cri := setGetClientCertificateCallback(conf, &cert)
	return conf, cri, nil
}

func setGetClientCertificateCallback(conf *tls.Config, cert *tls.Certificate) **tls.CertificateRequestInfo {
	var captured *tls.CertificateRequestInfo

	conf.GetClientCertificate = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		captured = cri
		return cert, nil
	}

	return &captured
}

// withDefaultPort takes an address and a port, and returns the address
// as-is if there's a port, or address:port if there isn't.
func withDefaultPort(addr string, portN uint16) string {
	port := strconv.Itoa(int(portN))
	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		// IPv6 without a port
		return net.JoinHostPort(addr, port)
	}
	if strings.ContainsAny(addr, ":") {
		// There are two cases when an address could contain a `:`
		// If it's an IPv6 address without a port, it's handled above
		// Otherwise, it's any kind of address with a port
		return addr
	}
	// No colon means no port.
	return net.JoinHostPort(addr, port)
}

// GetConnectionState connects to a TLS server, returning the connection state.
// startTLSType can be one of "mysql", "postgres", "psql", "smtp", "ldap",
// "ftp" or "imap", or the empty string, which does a normal TLS connection.
// connectTo specifies the address to connect to. connectName sets SNI.
// identity sets DB username or SMTP EHLO. connectCert and connectKey are
// client cert/key. Dialing, proxying, the STARTTLS exchange and the TLS
// handshake all share a single timeout budget, and the connection is closed
// and recycled before this function returns.
func GetConnectionState(startTLSType, connectName, connectTo, identity, clientCert, clientKey string, connectProxy *url.URL, timeout time.Duration) (*tls.ConnectionState, *tls.CertificateRequestInfo, error) {
	tlsConfig, cri, err := tlsConfigForConnect(connectName, connectTo, clientCert, clientKey)
	if err != nil {
		return nil, nil, err
	}

	// One absolute deadline bounds the whole connection lifecycle: TCP
	// establishment, the optional proxy CONNECT tunnel, the plaintext
	// STARTTLS exchange and the TLS handshake. It is enforced as a socket
	// deadline rather than a watchdog goroutine, so a timed-out attempt leaves
	// neither blocked goroutines nor half-open connections behind.
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}

	netDialer := newNetDialer(timeout, deadline)
	var dialer Dialer = netDialer
	if connectProxy != nil {
		dialer, err = wrapDialerWithProxy(netDialer, connectProxy, tlsConfig)
		if err != nil {
			return nil, nil, err
		}
	}

	var state *tls.ConnectionState
	switch startTLSType {
	case "":
		addr := withDefaultPort(connectTo, 443)
		state, err = dialAndUpgrade(dialer, "tcp", addr, tlsConfig, deadline, nil)
	case "ftp":
		addr := withDefaultPort(connectTo, 21)
		state, err = dialAndUpgrade(dialer, "tcp", addr, tlsConfig, deadline, ftpStartTLS())
	case "imap":
		addr := withDefaultPort(connectTo, 143)
		state, err = dialAndUpgrade(dialer, "tcp", addr, tlsConfig, deadline, imapStartTLS())
	case "smtp":
		addr := withDefaultPort(connectTo, 25)
		host, _, splitErr := net.SplitHostPort(addr)
		if splitErr != nil {
			return nil, nil, splitErr
		}
		state, err = dialAndUpgrade(dialer, "tcp", addr, tlsConfig, deadline, smtpStartTLS(host, identity))
	case "ldap":
		addr := withDefaultPort(connectTo, 389)
		state, err = dialAndUpgrade(dialer, "tcp", addr, tlsConfig, deadline, ldapStartTLS())
	case "mysql":
		if regErr := mysql.RegisterTLSConfig("certigo", tlsConfig); regErr != nil {
			err = fmt.Errorf("mysql registration error: %w", regErr)
			break
		}
		addr := withDefaultPort(connectTo, 3306)
		dsn := fmt.Sprintf("%s@tcp(%s)/?tls=certigo&timeout=%s", identity, addr, timeout.String())
		// The injected dial function routes MySQL through the (possibly
		// proxying) dialer and applies the shared deadline; the driver keeps
		// that deadline as long as no per-read/write timeouts are configured.
		dialFunc := func(addr string) (net.Conn, error) {
			return dialWithDeadline(dialer, "tcp", addr, deadline)
		}
		state, err = mysql.DumpTLS(dsn, dialFunc)
	case "postgres", "psql":
		// Setting sslmode to "require" skips verification. No connect_timeout
		// is passed: the shared deadline applied by the injected dialer also
		// covers the SSL negotiation and handshake.
		addr := withDefaultPort(connectTo, 5432)
		uri := fmt.Sprintf("postgres://%s@%s/?sslmode=require", identity, addr)
		if clientCert != "" {
			uri += fmt.Sprintf("&sslcert=%s", clientCert)
		}
		if clientKey != "" {
			uri += fmt.Sprintf("&sslkey=%s", clientCert)
		}
		state, err = pq.DumpTLSWithConfigAndDialer(uri, tlsConfig, pqDialerAdapter{dialer: dialer, deadline: deadline})
	default:
		err = fmt.Errorf("unknown StartTLS protocol: %s", startTLSType)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("error connecting: %w", err)
	}

	if cri == nil {
		return state, nil, nil
	}

	if state.Version < tls.VersionTLS12 && *cri != nil {
		// Sending supported signature schemes was added in TLS 1.2,
		// but Go lies to us in the GetClientCertificate callback and
		// gives us fake "supported schemes" even for older versions.
		// We clear the result here, otherwise it's a bit misleading.
		(*cri).SignatureSchemes = nil
	}

	return state, *cri, nil
}
