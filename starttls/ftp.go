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
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

func ftpStartTLS() startTLSFunc {
	return func(conn net.Conn, config *tls.Config) (*tls.ConnectionState, error) {
		// A single buffered reader must span the whole plaintext phase:
		// replies can share a TCP segment and a fresh bufio.Reader on every
		// read would silently discard whatever it over-read.
		reader := bufio.NewReader(conn)

		status, err := readFTPReply(reader)
		if err != nil {
			return nil, err
		}
		if status != 220 {
			return nil, fmt.Errorf("FTP server responded with status %d, was expecting 220", status)
		}

		if _, err := io.WriteString(conn, "AUTH TLS\r\n"); err != nil {
			return nil, err
		}

		status, err = readFTPReply(reader)
		if err != nil {
			return nil, err
		}
		if status != 234 {
			return nil, fmt.Errorf("FTP server refused AUTH TLS with status %d, was expecting 234", status)
		}

		tlsConn := tls.Client(&bufferedConn{reader: reader, Conn: conn}, config)
		if err := tlsConn.Handshake(); err != nil {
			return nil, err
		}

		state := tlsConn.ConnectionState()
		return &state, nil
	}
}

// readFTPReply consumes a complete FTP reply (RFC 959 section 4.2), waiting
// for the final line. Continuation lines look like "XYZ-text" while the final
// line is "XYZ text"; the "XYZ-" sequence may be repeated several times and
// replies may arrive split across arbitrarily many TCP segments.
func readFTPReply(r *bufio.Reader) (int, error) {
	code := -1
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return 0, err
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 3 {
			return 0, fmt.Errorf("error parsing FTP protocol: status code too short: %q", line)
		}
		lineCode, err := strconv.Atoi(line[:3])
		if err != nil {
			return 0, fmt.Errorf("error parsing FTP protocol: invalid status code %q: %w", line[:3], err)
		}
		if code == -1 {
			code = lineCode
		} else if lineCode != code {
			return 0, fmt.Errorf("error parsing FTP protocol: mismatched status codes in multiline reply: %d vs %d", code, lineCode)
		}

		switch {
		case len(line) == 3 || line[3] == ' ':
			// Final line of the reply.
			return code, nil
		case line[3] == '-':
			// Continuation line, keep reading.
			continue
		default:
			return 0, fmt.Errorf("error parsing FTP protocol: malformed reply line: %q", line)
		}
	}
}
