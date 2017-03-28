package noisesocket

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"math"

	"sync/atomic"

	"github.com/flynn/noise"
	"github.com/pkg/errors"
)

const MaxPayloadSize = math.MaxUint16

type VerifyCallbackFunc func(publicKey []byte, fields []*Field) error

type Conn struct {
	conn              net.Conn
	myKeys            noise.DHKey
	PeerKey           []byte
	in, out           halfConn
	handshakeMutex    sync.Mutex
	handshakeComplete bool
	isClient          bool
	handshakeErr      error
	input             *packet
	rawInput          *packet
	padding           uint16
	payload           []*Field
	// activeCall is an atomic int32; the low bit is whether Close has
	// been called. the rest of the bits are the number of goroutines
	// in Conn.Write.
	activeCall int32
	// handshakeCond, if not nil, indicates that a goroutine is committed
	// to running the handshake for this Conn. Other goroutines that need
	// to wait for the handshake can wait on this, under handshakeMutex.
	handshakeCond  *sync.Cond
	verifyCallback VerifyCallbackFunc
}

// Access to net.Conn methods.
// Cannot just embed net.Conn because that would
// export the struct Field too.

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated with the connection.
// A zero value for t means Read and Write will not time out.
// After a Write has timed out, the TLS state is corrupt and all future writes will return the same error.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the underlying connection.
// A zero value for t means Read will not time out.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying connection.
// A zero value for t means Write will not time out.
// After a Write has timed out, the TLS state is corrupt and all future writes will return the same error.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

var (
	errClosed = errors.New("tls: use of closed connection")
)

func (c *Conn) Write(b []byte) (int, error) {
	// interlock with Close below
	for {
		x := atomic.LoadInt32(&c.activeCall)
		if x&1 != 0 {
			return 0, errClosed
		}
		if atomic.CompareAndSwapInt32(&c.activeCall, x, x+2) {
			defer atomic.AddInt32(&c.activeCall, -2)
			break
		}
	}

	if err := c.Handshake(); err != nil {
		return 0, err
	}

	c.out.Lock()
	defer c.out.Unlock()
	if err := c.out.err; err != nil {
		return 0, err
	}

	if !c.handshakeComplete {
		return 0, errors.New("internal error")
	}

	n, err := c.writePacketLocked(b)
	return n, c.out.setErrorLocked(err)
}

func (c *Conn) writePacket(data []byte) (int, error) {
	c.out.Lock()
	defer c.out.Unlock()

	return c.writePacketLocked(data)
}

//InitializePacket adds additional sub-messages if needed
func (c *Conn) InitializePacket() *packet {
	block := c.out.newBlock()
	block.resize(uint16Size)
	return block
}

func (c *Conn) writePacketLocked(data []byte) (int, error) {

	var n int
	for len(data) > 0 {

		m := len(data)

		packet := c.InitializePacket()

		maxPayloadSize := c.maxPayloadSizeForWrite(packet)
		if m > int(maxPayloadSize) {
			m = int(maxPayloadSize)
		}

		if c.out.cs != nil {
			packet.AddField(data[:m], MessageTypeData)
		} else {
			packet.resize(len(packet.data) + len(data))
			copy(packet.data[uint16Size:len(packet.data)], data[:m])
			binary.BigEndian.PutUint16(packet.data, uint16(len(data)))
		}

		if c.out.cs != nil && c.padding == 0 {
			packet.AddPadding(c.padding)
		}

		b := c.out.encryptIfNeeded(packet)
		c.out.freeBlock(packet)

		if _, err := c.conn.Write(b); err != nil {
			return n, err
		}

		n += m
		data = data[m:]
	}

	return n, nil
}

func (c *Conn) maxPayloadSizeForWrite(block *packet) uint16 {
	res := MaxPayloadSize - uint16(len(block.data))
	if c.out.cs != nil {
		if c.padding > 0 {
			return res - macSize - msgHeaderSize*2
		} else {
			return res - macSize - msgHeaderSize
		}
	}
	return res

}

// Read reads data from the connection.
// Read can be made to time out and return a Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetReadDeadline.
func (c *Conn) Read(b []byte) (n int, err error) {
	if err = c.Handshake(); err != nil {
		return
	}
	if len(b) == 0 {
		// Put this after Handshake, in case people were calling
		// Read(nil) for the side effect of the Handshake.
		return
	}

	c.in.Lock()
	defer c.in.Unlock()

	if c.input == nil && c.in.err == nil {
		if err := c.readPacket(); err != nil {
			return 0, err
		}
	}

	if err := c.in.err; err != nil {
		return 0, err
	}
	n, err = c.input.Read(b)
	if c.input.off >= len(c.input.data) {
		c.in.freeBlock(c.input)
		c.input = nil
	}

	if ri := c.rawInput; ri != nil &&
		n != 0 && err == nil &&
		c.input == nil && len(ri.data) > 0 {
		if recErr := c.readPacket(); recErr != nil {
			err = recErr // will be io.EOF on closeNotify
		}
	}

	if n != 0 || err != nil {
		return n, err
	}

	return n, err
}

// readPacket reads the next noise packet from the connection
// and updates the record layer state.
// c.in.Mutex <= L; c.input == nil.
func (c *Conn) readPacket() error {

	if c.rawInput == nil {
		c.rawInput = c.in.newBlock()
	}
	b := c.rawInput

	// Read header, payload.
	if err := b.readFromUntil(c.conn, uint16Size); err != nil {
		if e, ok := err.(net.Error); !ok || !e.Temporary() {
			c.in.setErrorLocked(err)
		}
		return err
	}

	n := int(binary.BigEndian.Uint16(b.data))

	if err := b.readFromUntil(c.conn, uint16Size+n); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		if e, ok := err.(net.Error); !ok || !e.Temporary() {
			c.in.setErrorLocked(err)
		}
		return err
	}

	b, c.rawInput = c.in.splitBlock(b, uint16Size+n)

	payload, err := c.in.decryptIfNeeded(b)
	if err != nil {
		c.in.setErrorLocked(err)
		return err
	}

	in := c.in.newBlock()
	if c.in.cs != nil {
		messages, err := parseMessageFields(payload)

		if err != nil {
			c.in.setErrorLocked(err)
			return err
		}

		msg := messages[0]

		in.resize(len(msg.Data))
		copy(in.data, msg.Data)
	} else {
		in.resize(len(payload))
		copy(in.data, payload)
	}
	c.in.freeBlock(b)
	c.input = in
	return c.in.err
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (c *Conn) Close() error {
	// Interlock with Conn.Write above.
	var x int32
	for {
		x = atomic.LoadInt32(&c.activeCall)
		if x&1 != 0 {
			return errClosed
		}
		if atomic.CompareAndSwapInt32(&c.activeCall, x, x|1) {
			break
		}
	}
	if x != 0 {
		// io.Writer and io.Closer should not be used concurrently.
		// If Close is called while a Write is currently in-flight,
		// interpret that as a sign that this Close is really just
		// being used to break the Write and/or clean up resources and
		// avoid sending the alertCloseNotify, which may block
		// waiting on handshakeMutex or the c.out mutex.
		return c.conn.Close()
	}
	return c.conn.Close()
}

// Handshake runs the client or server handshake
// protocol if it has not yet been run.
// Most uses of this package need not call Handshake
// explicitly: the first Read or Write will call it automatically.
func (c *Conn) Handshake() error {
	// c.handshakeErr and c.handshakeComplete are protected by
	// c.handshakeMutex. In order to perform a handshake, we need to lock
	// c.in also and c.handshakeMutex must be locked after c.in.
	//
	// However, if a Read() operation is hanging then it'll be holding the
	// lock on c.in and so taking it here would cause all operations that
	// need to check whether a handshake is pending (such as Write) to
	// block.
	//
	// Thus we first take c.handshakeMutex to check whether a handshake is
	// needed.
	//
	// If so then, previously, this code would unlock handshakeMutex and
	// then lock c.in and handshakeMutex in the correct order to run the
	// handshake. The problem was that it was possible for a Read to
	// complete the handshake once handshakeMutex was unlocked and then
	// keep c.in while waiting for network data. Thus a concurrent
	// operation could be blocked on c.in.
	//
	// Thus handshakeCond is used to signal that a goroutine is committed
	// to running the handshake and other goroutines can wait on it if they
	// need. handshakeCond is protected by handshakeMutex.
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	for {
		if err := c.handshakeErr; err != nil {
			return err
		}
		if c.handshakeComplete {
			return nil
		}
		if c.handshakeCond == nil {
			break
		}

		c.handshakeCond.Wait()
	}

	// Set handshakeCond to indicate that this goroutine is committing to
	// running the handshake.
	c.handshakeCond = sync.NewCond(&c.handshakeMutex)
	c.handshakeMutex.Unlock()

	c.in.Lock()
	defer c.in.Unlock()

	c.handshakeMutex.Lock()

	if c.isClient {
		c.handshakeErr = c.RunClientHandshake()
	} else {
		c.handshakeErr = c.RunServerHandshake()
	}
	// Wake any other goroutines that are waiting for this handshake to
	// complete.
	c.handshakeCond.Broadcast()
	c.handshakeCond = nil

	return c.handshakeErr
}

func (c *Conn) RunClientHandshake() error {

	var (
		msg, payload []byte
		states       []*noise.HandshakeState
		err          error
		csIn, csOut  *noise.CipherState
	)

	b := c.out.newBlock()

	for _, f := range c.payload {
		b.AddField(f.Data, f.Type)
	}

	if msg, _, states, err = ComposeInitiatorHandshakeMessages(c.myKeys, c.PeerKey, b.data, nil); err != nil {
		return err
	}

	if _, err = c.writePacket(msg); err != nil {
		c.out.freeBlock(b)
		return err
	}
	c.out.freeBlock(b)

	//read server's answer
	if err := c.readPacket(); err != nil {
		return err
	}

	msg = c.input.data

	//preliminary checks
	if len(msg) < macSize+noise.DH25519.DHLen()+2 { // 2 is for index and IK's extra byte
		c.in.freeBlock(c.input)
		c.input = nil
		fmt.Println(len(msg), macSize+noise.DH25519.DHLen()*2)
		return errors.New("message is too small")
	}

	if int(msg[0]) > (len(states) - 1) {
		c.in.freeBlock(c.input)
		c.input = nil
		return errors.New("message index out of bounds")
	}

	//check for IK answer
	hs := states[msg[0]]
	offset := 1
	if len(hs.PeerStatic()) > 0 {
		mType := msg[1]

		if mType != 0 {
			c.in.freeBlock(c.input)
			c.input = nil
			return errors.New("Only pure IK is supported")
		}
		offset = 2
	}

	// cannot reuse msg for read, need another buf
	inblock := c.in.newBlock()
	inblock.reserve(len(msg))
	payload, csIn, csOut, err = hs.ReadMessage(inblock.data, msg[offset:])
	if err != nil {
		return err
	}
	c.in.freeBlock(inblock)
	c.in.freeBlock(c.input)
	c.input = nil

	if err = c.processPayload(hs.PeerStatic(), payload); err != nil {
		return err
	}

	if csIn == nil && csOut == nil {
		b = c.out.newBlock()
		if len(c.PeerKey) == 0 {
			outBlockPayload := c.out.newBlock()
			for _, f := range c.payload {
				outBlockPayload.AddField(f.Data, f.Type)
			}
			b.reserve(len(outBlockPayload.data) + 128)
			b.data, csIn, csOut = hs.WriteMessage(b.data, outBlockPayload.data)
			c.out.freeBlock(outBlockPayload)

		} else {
			b.data, csIn, csOut = hs.WriteMessage(b.data[:0], nil)
		}

		if _, err = c.writePacket(b.data); err != nil {
			c.out.freeBlock(b)
			return err
		}
		c.out.freeBlock(b)

		if csIn == nil || csOut == nil {
			panic("not supported")
		}

	}

	c.in.cs = csIn
	c.out.cs = csOut
	c.in.padding, c.out.padding = c.padding, c.padding
	c.handshakeComplete = true
	return nil
}

func (c *Conn) RunServerHandshake() error {

	var csOut, csIn *noise.CipherState
	if err := c.readPacket(); err != nil {
		return err
	}

	payload, hs, _, index, err := ParseHandshake(c.myKeys, c.input.data, -1, nil)

	c.in.freeBlock(c.input)
	c.input = nil

	if err != nil {
		return err
	}

	if err = c.processPayload(hs.PeerStatic(), payload); err != nil {
		return err
	}

	b := c.out.newBlock()
	b.resize(1)
	b.data[0] = index
	if len(hs.PeerStatic()) > 0 { //we answer to IK
		b.resize(2)
		b.data[1] = 0 // xx_fallback is not supported yet
	}

	//server can safely answer with payload as both XX and IK encrypt it
	off := len(b.data)

	outBlock := c.out.newBlock()

	for _, f := range c.payload {
		outBlock.AddField(f.Data, f.Type)
	}

	b.reserve(len(outBlock.data) + 128)
	b.data, csOut, csIn = hs.WriteMessage(b.data[:off], outBlock.data)
	c.out.freeBlock(outBlock)
	_, err = c.writePacket(b.data)
	c.out.freeBlock(b)

	if err != nil {
		return err
	}

	if csIn == nil && csOut == nil {

		if err := c.readPacket(); err != nil {
			return err
		}

		fmt.Println("got msg")
		inBlock := c.in.newBlock()
		inBlock.reserve(len(c.input.data))
		payload, csOut, csIn, err = hs.ReadMessage(inBlock.data, c.input.data)

		c.in.freeBlock(c.input)
		c.in.freeBlock(inBlock)
		c.input = nil

		if err != nil {
			return err
		}

		if err = c.processPayload(hs.PeerStatic(), payload); err != nil {
			return err
		}

		if csIn == nil || csOut == nil {
			return errors.New("Not supported")
		}
	}

	c.in.cs = csIn
	c.out.cs = csOut
	c.in.padding, c.out.padding = c.padding, c.padding
	c.handshakeComplete = true
	return nil
}

func (c *Conn) processPayload(publicKey []byte, payload []byte) error {
	if len(payload) > 0 && c.verifyCallback != nil {
		msgs, err := parseMessageFields(payload)

		if err != nil {
			return err
		}

		return c.verifyCallback(publicKey, msgs)
	}
	return nil
}
