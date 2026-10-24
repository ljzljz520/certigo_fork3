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

const imapStartTLSCommand = "1 STARTTLS"

func imapStartTLS() startTLSFunc {
	return func(conn net.Conn, config *tls.Config) (*tls.ConnectionState, error) {
		// A single buffered reader must span the whole plaintext phase: the
		// greeting can over-read, and creating a new bufio.Reader per response
		// would silently drop the buffered bytes.
		reader := bufio.NewReader(conn)

		status, err := readIMAPCompletion(reader, "")
		if err != nil {
			return nil, err
		}
		if status != "OK" {
			return nil, fmt.Errorf("IMAP server responded with %s, was expecting OK", status)
		}

		if _, err := io.WriteString(conn, imapStartTLSCommand+"\r\n"); err != nil {
			return nil, err
		}

		status, err = readIMAPCompletion(reader, "1")
		if err != nil {
			return nil, err
		}
		if status != "OK" {
			return nil, fmt.Errorf("IMAP server refused STARTTLS with %s response, was expecting OK", status)
		}

		tlsConn := tls.Client(&bufferedConn{reader: reader, Conn: conn}, config)
		if err := tlsConn.Handshake(); err != nil {
			return nil, err
		}

		state := tlsConn.ConnectionState()
		return &state, nil
	}
}

// readIMAPCompletion reads complete server responses up to the tagged
// completion line. Untagged ("*") and continuation ("+") lines, including any
// {n} literals, are consumed so the plaintext/TLS protocol boundary is
// respected. An empty tag waits for the server greeting, which is always
// untagged; a non-empty tag waits for that command's completion.
func readIMAPCompletion(r *bufio.Reader, tag string) (string, error) {
	for {
		line, err := readIMAPLine(r)
		if err != nil {
			return "", err
		}
		line = strings.TrimRight(line, "\r\n")

		var token, response string
		if i := strings.IndexByte(line, ' '); i >= 0 {
			token, response = line[:i], strings.TrimSpace(line[i+1:])
		} else {
			token = line
		}

		switch {
		case tag == "" && token == "*":
			// Server greeting: "* OK ...", "* PREAUTH ..." or "* BYE ...".
			return firstWord(response), nil
		case tag != "" && token == tag:
			// Tagged completion: "1 OK/NO/BAD ...".
			return firstWord(response), nil
		default:
			// Untagged or continuation data preceding the completion;
			// a greeting, on the other hand, must be untagged.
			if tag == "" {
				return "", fmt.Errorf("error parsing IMAP protocol: malformed server greeting: %q", line)
			}
		}
	}
}

// readIMAPLine returns one CRLF-terminated line, transparently consuming the
// literal payloads advertised by a trailing "{n}" marker (RFC 3501).
func readIMAPLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}

	trimmed := strings.TrimRight(line, "\r\n")
	if open := strings.LastIndexByte(trimmed, '{'); open >= 0 && strings.HasSuffix(trimmed, "}") {
		n, convErr := strconv.Atoi(trimmed[open+1 : len(trimmed)-1])
		if convErr != nil {
			return line, err
		}
		// The literal data and its trailing CRLF are not part of the reply
		// line, but must be consumed before parsing continues.
		if _, copyErr := io.CopyN(io.Discard, r, int64(n)+2); copyErr != nil {
			return "", copyErr
		}
		rest, joinErr := readIMAPLine(r)
		return line + rest, joinErr
	}

	return line, err
}

func firstWord(s string) string {
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i]
	}
	return s
}
