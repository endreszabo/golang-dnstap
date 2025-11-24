/*
 * Copyright (c) 2013-2019 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dnstap

import (
	"net"
	"time"
)

// A FrameStreamSockConnInput connects to a remote dnstap source and reads
// dnstap data from it. It maintains the connection and automatically
// reconnects on failure.
type FrameStreamSockConnInput struct {
	address       net.Addr
	timeout       time.Duration
	retryInterval time.Duration
	dialer        *net.Dialer
	log           Logger
	wait          chan bool
}

// NewFrameStreamSockConnInput creates a FrameStreamSockConnInput that will
// connect to the given address to receive dnstap data.
func NewFrameStreamSockConnInput(address net.Addr) *FrameStreamSockConnInput {
	return &FrameStreamSockConnInput{
		address:       address,
		retryInterval: 5 * time.Second,
		dialer: &net.Dialer{
			Timeout: 30 * time.Second,
		},
		log:  &nullLogger{},
		wait: make(chan bool),
	}
}

// SetTimeout sets the timeout for reading the initial handshake and writing
// response control messages on the connection.
func (input *FrameStreamSockConnInput) SetTimeout(timeout time.Duration) {
	input.timeout = timeout
}

// SetRetryInterval sets how long to wait between connection attempts.
// The default is 5 seconds.
func (input *FrameStreamSockConnInput) SetRetryInterval(interval time.Duration) {
	input.retryInterval = interval
}

// SetDialer sets the dialer used to establish connections.
func (input *FrameStreamSockConnInput) SetDialer(dialer *net.Dialer) {
	input.dialer = dialer
}

// SetLogger configures a logger for the FrameStreamSockConnInput.
func (input *FrameStreamSockConnInput) SetLogger(logger Logger) {
	input.log = logger
}

// ReadInto connects to the remote address and reads dnstap data from the
// connection, sending it to the output channel. On connection failure or
// disconnection, it automatically retries after the configured retry interval.
//
// ReadInto satisfies the dnstap Input interface.
func (input *FrameStreamSockConnInput) ReadInto(output chan []byte) {
	for {
		conn, err := input.dialer.Dial(input.address.Network(), input.address.String())
		if err != nil {
			input.log.Printf("%s: connection failed: %v", input.address, err)
			time.Sleep(input.retryInterval)
			continue
		}

		input.log.Printf("%s: connected", input.address)

		i, err := NewFrameStreamInputTimeout(conn, true, input.timeout)
		if err != nil {
			input.log.Printf("%s: failed to initialize frame stream: %v", input.address, err)
			conn.Close()
			time.Sleep(input.retryInterval)
			continue
		}

		i.SetLogger(input.log)
		i.ReadInto(output)
		i.Wait()

		input.log.Printf("%s: disconnected, reconnecting...", input.address)
		conn.Close()
		time.Sleep(input.retryInterval)
	}
}

// Wait satisfies the dnstap Input interface.
//
// The FrameStreamSockConnInput Wait method never returns, because the
// corresponding ReadInto method continuously attempts to maintain a connection.
func (input *FrameStreamSockConnInput) Wait() {
	select {}
}
