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

	"github.com/go-ldap/ldap/v3"
)

// ldapStartTLS performs an LDAP StartTLS extended operation on an
// already-dialed connection, so LDAP probes honor the same dialer (and proxy)
// as every other protocol. ldap.Conn.Start launches reader/writer goroutines,
// which is why the connection is always closed before returning: Close stops
// both goroutines and reaps the underlying socket. The connection deadline
// set by dialAndUpgrade bounds the extended-response wait and the handshake.
func ldapStartTLS() startTLSFunc {
	return func(conn net.Conn, config *tls.Config) (*tls.ConnectionState, error) {
		l := ldap.NewConn(conn, false)
		l.Start()
		defer func() { _ = l.Close() }()

		if err := l.StartTLS(config); err != nil {
			return nil, err
		}

		state, ok := l.TLSConnectionState()
		if !ok {
			return nil, fmt.Errorf("LDAP connection isn't TLS after StartTLS")
		}
		return &state, nil
	}
}
