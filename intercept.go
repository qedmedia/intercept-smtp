// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package smtp implements the Simple Mail Transfer Protocol as defined in RFC 5321.
// It also implements the following extensions:
//	8BITMIME  RFC 1652
//	AUTH      RFC 2554
//	STARTTLS  RFC 3207
// Additional extensions may be handled by clients.
package intercept_smtp

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
)

var ErrorAbort = errors.New("operation abort");

type ReviewResult int
const (
        ProceedCommand ReviewResult = iota
        AbortCommand
)

type Interceptor interface {
        ReviewClientDataError(err error)
        ReviewClientDataBytes(bs []byte) ReviewResult
        ReviewClientMessage(code int, format string, args ...interface{}) ReviewResult
        ReviewServerMessage(code int, message string, err error)
}

// A InterceptClient represents a client connection to an SMTP server,
// it's basically the same as smtp.Client, plus addition to allow intercepting
// a SMTP section.
type InterceptClient struct {
	// Text is the textproto.Conn used by the InterceptClient. It is exported to allow for
	// clients to add extensions.
	Text *textproto.Conn
	// keep a reference to the connection so it can be used to create a TLS
	// connection later
	conn net.Conn
	// whether the InterceptClient is using TLS
	tls        bool
	serverName string
	// map of supported extensions
	ext map[string]string
	// supported auth mechanisms
	auth       []string
	localName  string // the name to use in HELO/EHLO
	didHello   bool   // whether we've said HELO/EHLO
	helloError error  // the error from the hello
        intercept Interceptor // interceptor for the active section
}

type TransparentInterceptor struct {
}

func (ti *TransparentInterceptor) ReviewClientMessage(code int, format string, args ...interface{}) ReviewResult {
        return ProceedCommand
}

func (ti *TransparentInterceptor) ReviewClientDataBytes(bs []byte) ReviewResult {
        return ProceedCommand
}

func (ti *TransparentInterceptor) ReviewClientDataError(err error) {
}

func (ti *TransparentInterceptor) ReviewServerMessage(code int, message string, err error) {
}

// Dial returns a new InterceptClient connected to an SMTP server at addr.
// The addr must include a port, as in "mail.example.com:smtp".
func Dial(interceptor Interceptor, addr string) (*InterceptClient, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
                interceptor.ReviewServerMessage(-1, "", err)
		return nil, err
	}
	host, _, _ := net.SplitHostPort(addr)
	return NewInterceptClient(interceptor, conn, host)
}

// NewInterceptClient returns a new InterceptClient using an existing connection and host as a
// server name to be used when authenticating.
func NewInterceptClient(interceptor Interceptor, conn net.Conn, host string) (*InterceptClient, error) {
        if interceptor.ReviewClientMessage(220, host) == AbortCommand {
                return nil, ErrorAbort
        }

	text := textproto.NewConn(conn)
	code, msg, err := text.ReadResponse(220)
	if err != nil {
		text.Close()
		return nil, err
	}

        interceptor.ReviewServerMessage(code, msg, err)

	c := &InterceptClient{
                Text: text,
                conn: conn,
                serverName: host,
                localName: "localhost",
                intercept: interceptor,
        }

	return c, nil
}

// Close closes the connection.
func (c *InterceptClient) Close() error {
	return c.Text.Close()
}

// hello runs a hello exchange if needed.
func (c *InterceptClient) hello() error {
	if !c.didHello {
		c.didHello = true
		err := c.ehlo()
		if err != nil {
			c.helloError = c.helo()
		}
	}
	return c.helloError
}

// Hello sends a HELO or EHLO to the server as the given host name.
// Calling this method is only necessary if the client needs control
// over the host name used.  The client will introduce itself as "localhost"
// automatically otherwise.  If Hello is called, it must be called before
// any of the other methods.
func (c *InterceptClient) Hello(localName string) error {
	if c.didHello {
		return errors.New("smtp: Hello called after other methods")
	}
	c.localName = localName
	return c.hello()
}

// cmd is a convenience function that sends a command and returns the response
func (c *InterceptClient) cmd(expectCode int, format string, args ...interface{}) (int, string, error) {
        if c.intercept.ReviewClientMessage(expectCode, format, args...) == AbortCommand {
                return 0, "", ErrorAbort
        }

	id, err := c.Text.Cmd(format, args...)
	if err != nil {
		return 0, "", err
	}
	c.Text.StartResponse(id)
	defer c.Text.EndResponse(id)
	code, msg, err := c.Text.ReadResponse(expectCode)
        c.intercept.ReviewServerMessage(code, msg, err)
	return code, msg, err
}

// helo sends the HELO greeting to the server. It should be used only when the
// server does not support ehlo.
func (c *InterceptClient) helo() error {
	c.ext = nil
	_, _, err := c.cmd(250, "HELO %s", c.localName)
	return err
}

// ehlo sends the EHLO (extended hello) greeting to the server. It
// should be the preferred greeting for servers that support it.
func (c *InterceptClient) ehlo() error {
	_, msg, err := c.cmd(250, "EHLO %s", c.localName)
	if err != nil {
		return err
	}
	ext := make(map[string]string)
	extList := strings.Split(msg, "\n")
	if len(extList) > 1 {
		extList = extList[1:]
		for _, line := range extList {
			args := strings.SplitN(line, " ", 2)
			if len(args) > 1 {
				ext[args[0]] = args[1]
			} else {
				ext[args[0]] = ""
			}
		}
	}
	if mechs, ok := ext["AUTH"]; ok {
		c.auth = strings.Split(mechs, " ")
	}
	c.ext = ext
	return err
}

// StartTLS sends the STARTTLS command and encrypts all further communication.
// Only servers that advertise the STARTTLS extension support this function.
func (c *InterceptClient) StartTLS(config *tls.Config) error {
	if err := c.hello(); err != nil {
		return err
	}
	_, _, err := c.cmd(220, "STARTTLS")
	if err != nil {
		return err
	}
	c.conn = tls.Client(c.conn, config)
	c.Text = textproto.NewConn(c.conn)
	c.tls = true
	return c.ehlo()
}

// TLSConnectionState returns the client's TLS connection state.
// The return values are their zero values if StartTLS did
// not succeed.
func (c *InterceptClient) TLSConnectionState() (state tls.ConnectionState, ok bool) {
	tc, ok := c.conn.(*tls.Conn)
	if !ok {
		return
	}
	return tc.ConnectionState(), true
}

// Verify checks the validity of an email address on the server.
// If Verify returns nil, the address is valid. A non-nil return
// does not necessarily indicate an invalid address. Many servers
// will not verify addresses for security reasons.
func (c *InterceptClient) Verify(addr string) error {
	if err := c.hello(); err != nil {
		return err
	}
	_, _, err := c.cmd(250, "VRFY %s", addr)
	return err
}

// Auth authenticates a client using the provided authentication mechanism.
// A failed authentication closes the connection.
// Only servers that advertise the AUTH extension support this function.
func (c *InterceptClient) Auth(a smtp.Auth) error {

	if err := c.hello(); err != nil {
		return err
	}
	encoding := base64.StdEncoding

	// Work around for change in Golang where they detect if server.TLS is false.
	c.tls = true

	mech, resp, err := a.Start(&smtp.ServerInfo{c.serverName, c.tls, c.auth})
	if err != nil {
		c.Quit()
		return err
	}
	resp64 := make([]byte, encoding.EncodedLen(len(resp)))
	encoding.Encode(resp64, resp)
	code, msg64, err := c.cmd(0, "AUTH %s %s", mech, resp64)
	for err == nil {
		var msg []byte
		switch code {
		case 334:
			msg, err = encoding.DecodeString(msg64)
		case 235:
			// the last message isn't base64 because it isn't a challenge
			msg = []byte(msg64)
		default:
			err = &textproto.Error{Code: code, Msg: msg64}
		}
		if err == nil {
			resp, err = a.Next(msg, code == 334)
		}
		if err != nil {
			// abort the AUTH
			c.cmd(501, "*")
			c.Quit()
			break
		}
		if resp == nil {
			break
		}
		resp64 = make([]byte, encoding.EncodedLen(len(resp)))
		encoding.Encode(resp64, resp)
		code, msg64, err = c.cmd(0, string(resp64))
	}
	return err
}

// Mail issues a MAIL command to the server using the provided email address.
// If the server supports the 8BITMIME extension, Mail adds the BODY=8BITMIME
// parameter.
// This initiates a mail transaction and is followed by one or more Rcpt calls.
func (c *InterceptClient) Mail(from string) error {
	if err := c.hello(); err != nil {
		return err
	}
	cmdStr := "MAIL FROM:<%s>"
	if c.ext != nil {
		if _, ok := c.ext["8BITMIME"]; ok {
			cmdStr += " BODY=8BITMIME"
		}
	}
	_, _, err := c.cmd(250, cmdStr, from)
	return err
}

// Rcpt issues a RCPT command to the server using the provided email address.
// A call to Rcpt must be preceded by a call to Mail and may be followed by
// a Data call or another Rcpt call.
func (c *InterceptClient) Rcpt(to string) error {
	_, _, err := c.cmd(25, "RCPT TO:<%s>", to)
	return err
}

type dataWriteCloser struct {
	c *InterceptClient
	wc io.WriteCloser
}

func (d *dataWriteCloser) Write(p []byte) (n int, err error) {
        if d.c.intercept.ReviewClientDataBytes(p) == AbortCommand {
                return 0, ErrorAbort
        }
        if n, err = d.wc.Write(p); err != nil {
                d.c.intercept.ReviewClientDataError(err)
        }
        return
}

func (d *dataWriteCloser) Close() error {
	d.wc.Close()
	code, msg, err := d.c.Text.ReadResponse(250)
        d.c.intercept.ReviewServerMessage(code, msg, err)
	return err
}

// Data issues a DATA command to the server and returns a writer that
// can be used to write the mail headers and body. The caller should
// close the writer before calling any more methods on c.  A call to
// Data must be preceded by one or more calls to Rcpt.
func (c *InterceptClient) Data() (io.WriteCloser, error) {
	_, _, err := c.cmd(354, "DATA")
	if err != nil {
		return nil, err
	}
	return &dataWriteCloser{c, c.Text.DotWriter()}, nil
}

// Extension reports whether an extension is support by the server.
// The extension name is case-insensitive. If the extension is supported,
// Extension also returns a string that contains any parameters the
// server specifies for the extension.
func (c *InterceptClient) Extension(ext string) (bool, string) {
	if err := c.hello(); err != nil {
		return false, ""
	}
	if c.ext == nil {
		return false, ""
	}
	ext = strings.ToUpper(ext)
	param, ok := c.ext[ext]
	return ok, param
}

// Reset sends the RSET command to the server, aborting the current mail
// transaction.
func (c *InterceptClient) Reset() error {
	if err := c.hello(); err != nil {
		return err
	}
	_, _, err := c.cmd(250, "RSET")
	return err
}

// Quit sends the QUIT command and closes the connection to the server.
func (c *InterceptClient) Quit() error {
	if err := c.hello(); err != nil {
		return err
	}
	_, _, err := c.cmd(221, "QUIT")
	if err != nil {
		return err
	}
	return c.Text.Close()
}
