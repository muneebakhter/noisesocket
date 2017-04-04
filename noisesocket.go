package noisesocket

import (
	"net"

	"github.com/flynn/noise"
)

// A listener implements a network listener (net.Listener) for TLS connections.
type listener struct {
	net.Listener
	key               noise.DHKey
	payload           []*Field
	verifyCallback    VerifyCallbackFunc
	handshakeStrategy int
	maxPacketSize     uint16
}

// Accept waits for and returns the next incoming TLS connection.
// The returned connection is of type *Conn.
func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &Conn{
		conn:              c,
		myKeys:            l.key,
		padding:           128,
		payload:           l.payload,
		verifyCallback:    l.verifyCallback,
		HandshakeStrategy: l.handshakeStrategy,
		MaxPacketSize:     l.maxPacketSize,
	}, nil
}

// Listen creates a TLS listener accepting connections on the
// given network address using net.Listen.
func Listen(network, laddr string, key noise.DHKey, payload []*Field, verifyCallback VerifyCallbackFunc, handshakeStrategy int, maxPacketSize uint16) (net.Listener, error) {

	l, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return &listener{
		Listener:          l,
		key:               key,
		payload:           payload,
		verifyCallback:    verifyCallback,
		handshakeStrategy: handshakeStrategy,
		maxPacketSize:     maxPacketSize,
	}, nil
}

func Dial(network, addr string, key noise.DHKey, serverKey []byte, payload []*Field, callbackFunc VerifyCallbackFunc, maxPacketSize uint16) (*Conn, error) {
	rawConn, err := new(net.Dialer).Dial(network, addr)
	if err != nil {
		return nil, err
	}

	return &Conn{
		conn:           rawConn,
		myKeys:         key,
		PeerKey:        serverKey,
		isClient:       true,
		padding:        128,
		payload:        payload,
		verifyCallback: callbackFunc,
		MaxPacketSize:  maxPacketSize,
	}, nil
}
