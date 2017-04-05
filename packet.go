package noisesocket

import (
	"encoding/binary"
	"io"
	"math"
)

// A packet is a simple data buffer.
type packet struct {
	data []byte
	off  int // index for Read
	link *packet
}

// resize resizes packet to be n bytes, growing if necessary.
func (b *packet) resize(n int) {
	if n > cap(b.data) {
		b.reserve(n)
	}
	b.data = b.data[0:n]
}

// reserve makes sure that packet contains a capacity of at least n bytes.
func (b *packet) reserve(n int) {
	if cap(b.data) >= n {
		return
	}
	m := cap(b.data)
	if m == 0 {
		m = 1024
	}
	for m < n {
		m *= 2
	}
	data := make([]byte, len(b.data), m)
	copy(data, b.data)
	b.data = data
}

// readFromUntil reads from r into b until b contains at least n bytes
// or else returns an error.
func (b *packet) readFromUntil(r io.Reader, n int) error {
	// quick case
	if len(b.data) >= n {
		return nil
	}

	// read until have enough.
	b.reserve(n)
	for {
		m, err := r.Read(b.data[len(b.data):cap(b.data)])
		b.data = b.data[0 : len(b.data)+m]
		if len(b.data) >= n {
			// TODO(bradfitz,agl): slightly suspicious
			// that we're throwing away r.Read's err here.
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *packet) Read(p []byte) (n int, err error) {
	n = copy(p, b.data[b.off:])
	b.off += n
	return
}

func (b *packet) AddPadding(padding uint16, maxPacketSize uint16) {
	if maxPacketSize == 0 {
		maxPacketSize = MaxPayloadSize
	}
	rawDataLen := len(b.data)

	payloadSize := rawDataLen + msgHeaderSize /*zero padding*/ + macSize - uint16Size /*packet header*/

	if payloadSize > int(maxPacketSize) {
		panic("no space left for padding")
	}

	paddingSize := uint16(0)
	if padding > 0 {
		paddingSize = padding - uint16(payloadSize)%padding
	}

	if payloadSize+int(paddingSize) > int(maxPacketSize) {
		paddingSize = maxPacketSize - uint16(payloadSize)
	}

	b.resize(int(rawDataLen + msgHeaderSize + int(paddingSize)))
	binary.BigEndian.PutUint16(b.data[rawDataLen:], uint16(paddingSize+uint16Size))
	binary.BigEndian.PutUint16(b.data[rawDataLen+2:], MessageTypePadding)
}

func (b *packet) AddField(data []byte, msgType uint16) {

	b.reserve(len(b.data) + len(data) + msgHeaderSize)
	b.data = append(b.data, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(b.data[len(b.data)-4:], uint16(len(data)+uint16Size))
	binary.BigEndian.PutUint16(b.data[len(b.data)-2:], msgType)
	b.data = append(b.data, data...)

	if len(b.data) > math.MaxUint16 {
		panic("packet is too big")
	}
}
