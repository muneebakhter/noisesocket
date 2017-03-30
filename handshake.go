package noisesocket

import (
	"encoding/binary"
	"math"

	"crypto/rand"

	"bytes"
	"io"

	"github.com/flynn/noise"
	"github.com/pkg/errors"
)

type HandshakeMessage struct {
	Config  *HandshakeConfig
	Message []byte
}

func ComposeInitiatorHandshakeMessages(s noise.DHKey, rs []byte, payload []byte, ePrivate []byte) (msg []byte, prologue []byte, states []*noise.HandshakeState, err error) {

	if len(rs) != 0 && len(rs) != noise.DH25519.DHLen() {
		return nil, nil, nil, errors.New("only 32 byte curve25519 public keys are supported")
	}
	res := make([]byte, 0, 2048)

	usedPatterns := []noise.HandshakePattern{noise.HandshakeXX}

	prologue = make([]byte, 1, 1024)

	//we checked this in init
	prologue[0] = byte(len(protoCipherPriorities[noise.HandshakeXX.Name]))

	prologue = append(prologue, prologues[noise.HandshakeXX.Name]...)

	//add IK if remote static is provided
	if len(rs) > 0 {
		usedPatterns = append(usedPatterns, noise.HandshakeIK)
		prologue = append(prologue, prologues[noise.HandshakeIK.Name]...)

		if len(protoCipherPriorities[noise.HandshakeIK.Name])+int(prologue[0]) > math.MaxUint8 {
			return nil, nil, nil, errors.New("too many sub-messages for a single message")
		}

		prologue[0] += byte(len(protoCipherPriorities[noise.HandshakeIK.Name]))
	}

	states = make([]*noise.HandshakeState, 0, prologue[0])

	for _, pattern := range usedPatterns {

		for _, csp := range protoCipherPriorities[pattern.Name] {
			cfg := handshakeConfigs[csp]

			msg := res[len(res):] //append to res

			//append message type : 1 byte len + len bytes type name

			msg = append(msg, cfg.NameLength)
			msg = append(msg, cfg.Name...)

			res = append(res, msg...)

			//reset position
			msg = msg[len(msg):]

			//append cipher suite contents : 2 byte len + len bytes message.

			msg = append(msg, 0, 0) // add 2 bytes for length

			rs := rs
			if !cfg.UseRemoteStatic {
				rs = nil
			}
			var random io.Reader
			if len(ePrivate) == 0 {
				random = rand.Reader
			} else {
				random = bytes.NewBuffer(ePrivate)
			}
			state := noise.NewHandshakeState(noise.Config{
				StaticKeypair: s,
				Initiator:     true,
				Pattern:       cfg.Pattern,
				CipherSuite:   noise.NewCipherSuite(cfg.DH, cfg.Cipher, cfg.Hash),
				PeerStatic:    rs,
				Prologue:      prologue,
				Random:        random,
			})

			if CanWrite(cfg.Pattern, 0) {
				msg, _, _ = state.WriteMessage(msg, payload)
			} else {
				msg, _, _ = state.WriteMessage(msg, nil)
			}

			binary.BigEndian.PutUint16(msg, uint16(len(msg)-uint16Size)) //write calculated length at the beginning

			states = append(states, state)

			// we cannot send the message if its length exceeds 2^16 - 1
			if len(res)+len(msg) > (math.MaxUint16 - uint16Size) {
				return nil, nil, nil, errors.New("Message is too big")
			}
			res = append(res, msg...)

		}
	}
	return res, prologue, states, nil
}

func CanWrite(pattern noise.HandshakePattern, msgIndex int) bool {
	for _, m := range pattern.Messages[msgIndex] {
		if m == noise.MessagePatternS {
			return true
		}
	}
	return false
}

func ParseHandshake(s noise.DHKey, handshake []byte, prefferedIndex int, ePrivate []byte) (payload []byte, hs *noise.HandshakeState, hcfg *HandshakeConfig, messageIndex byte, err error) {

	parsedPrologue := make([]byte, 1, 1024)
	messages := make([]*HandshakeMessage, 0, 16)
	for {
		if len(handshake) == 0 {
			break
		}

		if parsedPrologue[0] == math.MaxUint8 {
			err = errors.New("too many messages")
			return
		}

		var typeName, msg []byte
		handshake, typeName, err = readData(handshake, 1) //read protocol name

		if err != nil {
			return
		}

		parsedPrologue = append(parsedPrologue, byte(len(typeName)))
		parsedPrologue = append(parsedPrologue, typeName...)

		handshake, msg, err = readData(handshake, 2) //read handshake data

		if err != nil {
			return
		}

		//lookup protocol config

		nameKey := HashKey(typeName)
		cfg, ok := handshakeConfigs[nameKey]
		if ok {

			messages = append(messages, &HandshakeMessage{
				Config:  cfg,
				Message: msg,
			})
		}

		parsedPrologue[0]++

	}

	var random io.Reader
	if len(ePrivate) == 0 {
		random = rand.Reader
	} else {
		random = bytes.NewBuffer(ePrivate)
	}

	//choose protocol that we want to use, according to server priorities
	if prefferedIndex == -1 {
		for _, pr := range protoPriorities {
			for _, p := range protoCipherPriorities[pr] {
				for i, m := range messages {
					if p == m.Config.NameKey {

						state, payload, err := getState(m, s, parsedPrologue, random)

						if err != nil {
							return nil, nil, nil, 0, err
						}

						return payload, state, m.Config, byte(i), nil
					}
				}

			}
		}
	} else if prefferedIndex == -2 {
		//choose randomly
		max := len(messages)
		b := make([]byte, 1)
		rand.Read(b)

		index := int(b[0]) % max
		m := messages[index]

		state, payload, err := getState(m, s, parsedPrologue, random)

		if err != nil {
			return nil, nil, nil, 0, err
		}

		return payload, state, m.Config, byte(index), nil

	} else {
		m := messages[prefferedIndex]
		state, payload, err := getState(m, s, parsedPrologue, random)

		if err != nil {
			return nil, nil, nil, 0, err
		}

		return payload, state, m.Config, byte(prefferedIndex), nil
	}
	err = errors.New("no supported protocols found")
	return
}

func getState(m *HandshakeMessage, s noise.DHKey, parsedPrologue []byte, random io.Reader) (*noise.HandshakeState, []byte, error) {
	state := noise.NewHandshakeState(noise.Config{
		StaticKeypair: s,
		Pattern:       m.Config.Pattern,
		CipherSuite:   noise.NewCipherSuite(m.Config.DH, m.Config.Cipher, m.Config.Hash),
		Prologue:      parsedPrologue,
		Random:        random,
	})

	payload, _, _, err := state.ReadMessage(nil, m.Message)
	return state, payload, err
}

func readData(data []byte, sizeBytes int) (rest []byte, msg []byte, err error) {
	if sizeBytes != 1 && sizeBytes != 2 {
		return nil, nil, errors.New("only 1 and 2 byte lengths are supported")
	}

	if len(data) < sizeBytes {
		return nil, nil, errors.New("buffer too small")
	}

	msgLen := 0

	switch sizeBytes {
	case 1:
		msgLen = int(data[0])
		break
	case 2:
		msgLen = int(binary.BigEndian.Uint16(data))
		break

	}

	if msgLen == 0 {
		return nil, nil, errors.New("zero length messages are not supported")
	}

	if len(data) < (msgLen + sizeBytes) {
		return nil, nil, errors.New("invalid length")
	}

	rest = data[(msgLen + sizeBytes):]
	msg = data[sizeBytes:(msgLen + sizeBytes)]

	return rest, msg, nil
}
