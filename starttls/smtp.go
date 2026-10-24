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
	"errors"
	"net"
	"net/smtp"
)

// smtpStartTLS performs an SMTP STARTTLS upgrade on an already-dialed
// connection, so SMTP probes honor the same dialer (and proxy) as every other
// protocol. The connection deadline set by dialAndUpgrade bounds the greeting,
// EHLO and handshake phases; net/smtp itself spawns no goroutines.
func smtpStartTLS(host, identity string) startTLSFunc {
	return func(conn net.Conn, config *tls.Config) (*tls.ConnectionState, error) {
		client, err := smtp.NewClient(conn, host)
		if err != nil {
			return nil, err
		}

		if identity != "" {
			if err := client.Hello(identity); err != nil {
				return nil, err
			}
		}

		if err := client.StartTLS(config); err != nil {
			return nil, err
		}

		state, ok := client.TLSConnectionState()
		if !ok {
			return nil, errors.New("SMTP connection isn't TLS after StartTLS")
		}
		return &state, nil
	}
}
