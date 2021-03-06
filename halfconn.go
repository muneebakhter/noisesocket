package noisesocket

import (
	"encoding/binary"
	"errors"
	"sync"

	"github.com/flynn/noise"
)

//halfConn represents inbound or outbound connection state with its own cipher
type halfConn struct {
	sync.Mutex
	cs      *noise.CipherState
	err     error
	bfree   *packet // list of free blocks
	padding uint16
}

const (
	uint16Size    = 2  // uint16 takes 2 bytes
	msgHeaderSize = 4  // message inside packet has type and length
	macSize       = 16 // GCM and Poly1305 add 16 byte MACs
)

// encryptIfNeeded prepares packet structure depending on padding and data length.
// It also encrypts it if cipher is set up (handshake is done)
func (h *halfConn) encryptIfNeeded(block *packet) []byte {

	if h.cs != nil {

		payloadSize := len(block.data) - uint16Size + macSize
		if payloadSize > MaxPayloadSize {
			panic("data is too big to be sent")
		}

		block.data = h.cs.Encrypt(block.data[:uint16Size], nil, block.data[uint16Size:])
		binary.BigEndian.PutUint16(block.data, uint16(payloadSize))

		return block.data
	}

	if len(block.data) > MaxPayloadSize-uint16Size {
		panic("data is too big to be sent")
	}

	binary.BigEndian.PutUint16(block.data, uint16(len(block.data)-uint16Size))

	return block.data
}

// decryptIfNeeded checks and strips the mac and decrypts the data in b.
// Returns error if parsing failed

func (h *halfConn) decryptIfNeeded(b *packet) (data []byte, err error) {

	if len(b.data) < (uint16Size * 3) {
		return nil, errors.New("packet is too small")
	}
	// pull out payload

	payload := b.data[uint16Size:]

	packetLen := binary.BigEndian.Uint16(b.data)
	if int(packetLen) != len(payload) { //this is supposed to be checked before method call
		panic("invalid payload size")
	}

	if h.cs != nil {
		payload, err = h.cs.Decrypt(payload[:0], nil, payload)
		if err != nil {
			return nil, err
		}
		return payload, nil
	}

	return payload, nil
}

func (h *halfConn) setErrorLocked(err error) error {
	h.err = err
	return err
}

// newBlock allocates a new packet, from hc's free list if possible.
func (h *halfConn) newBlock() *packet {
	b := h.bfree
	if b == nil {
		return new(packet)

	}
	h.bfree = b.link
	b.link = nil
	b.resize(0)
	b.off = 0
	return b
}

// freeBlock returns a packet to hc's free list.
// The protocol is such that each side only has a packet or two on
// its free list at a time, so there's no need to worry about
// trimming the list, etc.
func (h *halfConn) freeBlock(b *packet) {
	b.link = h.bfree
	h.bfree = b

}

// splitBlock splits a packet after the first n bytes,
// returning a packet with those n bytes and a
// packet with the remainder.  the latter may be nil.
func (h *halfConn) splitBlock(b *packet, n int) (*packet, *packet) {
	if len(b.data) <= n {
		return b, nil
	}
	bb := h.newBlock()
	bb.resize(len(b.data) - n)
	copy(bb.data, b.data[n:])
	b.data = b.data[0:n]
	return b, bb
}
