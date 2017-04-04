package noisesocket

import (
	"encoding/binary"
	"errors"
)

const (
	MessageTypePadding uint16 = iota
	MessageTypeData
	MessageTypeMaxPacketSize
	MessageTypeCustomCert = 1024
	MessageTypeSignature  = 1025
)

type Field struct {
	Type uint16
	Data []byte
}

func parseMessageFields(payload []byte) ([]*Field, error) {

	if len(payload) == 0 {
		return nil, nil
	}
	if len(payload) < msgHeaderSize {
		return nil, errors.New("payload too small")
	}

	msgs := make([]*Field, 0, 1)

	off := uint16(0)
	for {
		msgLen := binary.BigEndian.Uint16(payload[off:])
		if int(off+msgLen) > len(payload) {
			return nil, errors.New("invalid size")
		}

		off += 2
		msgType := binary.BigEndian.Uint16(payload[off:])
		off += 2
		msgs = append(msgs, &Field{
			Type: msgType,
			Data: payload[off : off+msgLen-uint16Size],
		})
		off += msgLen - uint16Size
		if int(off) >= (len(payload) - msgHeaderSize) {
			break
		}
	}
	return msgs, nil
}
