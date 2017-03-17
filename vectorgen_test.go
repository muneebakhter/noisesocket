package noisesocket

import (
	"crypto/rand"

	"encoding/binary"
	"encoding/hex"
	"fmt"

	"bytes"
	"testing"

	"encoding/json"

	"github.com/flynn/noise"
)

type Vector struct {
	Name string `json:"name"`

	Prologue         string     `json:"init_prologue"`
	InitStatic       string     `json:"init_static"`
	InitEphemeral    string     `json:"init_ephemeral"`
	InitRemoteStatic string     `json:"init_remote_static"`
	RespStatic       string     `json:"resp_static"`
	RespEphemeral    string     `json:"resp_ephemeral"`
	InitialMessage   string     `json:"initial_message"`
	Sessions         []*Session `json:"sessions"`
}

type Session struct {
	Index             byte       `json:"index"`
	Pattern           string     `json:"pattern"`
	Dh                string     `json:"dh"`
	Cipher            string     `json:"cipher"`
	Hash              string     `json:"hash"`
	HandshakeHash     string     `json:"handshake_hash"`
	HandshakeMessages []*Message `json:"handshake_messages"`
	TransportMessages []*Message `json:"transport_messages"`
}

type Message struct {
	Payload    string            `json:"payload"`
	Fields     map[uint16]string `json:"fields"`
	Ciphertext string            `json:"ciphertext"`
}

func TestVectors(t *testing.T) {

	si, sr, ei, er := make([]byte, 0, 32), make([]byte, 0, 32), make([]byte, 0, 32), make([]byte, 0, 32)
	for i := byte(0); i < 32; i++ {
		ei = append(ei, i%2)
		er = append(er, i%3)
		si = append(si, i%4)
		sr = append(sr, i%5)
	}

	ki := noise.DH25519.GenerateKeypair(bytes.NewBuffer(si))
	kr := noise.DH25519.GenerateKeypair(bytes.NewBuffer(sr))

	clientCert := []byte(`{owner:"alice@client.com"}`)
	serverCert := []byte(`{owner:"bob@server.com"}`)

	vec := &Vector{
		Name:             "NoiseSocket",
		InitEphemeral:    hex.EncodeToString(ei),
		InitStatic:       hex.EncodeToString(si),
		InitRemoteStatic: hex.EncodeToString(kr.Public),
		RespEphemeral:    hex.EncodeToString(er),
		RespStatic:       hex.EncodeToString(sr),
	}

	pkt := new(packet)
	pkt.AddField(clientCert, MessageTypeCustomCert)

	ihm, prologue, iStates, err := ComposeInitiatorHandshakeMessages(ki, kr.Public, pkt.data, ei)
	if err != nil {
		panic(err)
	}
	vec.Prologue = hex.EncodeToString(prologue)

	pkt = InitializePacket()

	pkt.resize(len(pkt.data) + len(ihm))
	copy(pkt.data[uint16Size:len(pkt.data)], ihm)
	binary.BigEndian.PutUint16(pkt.data, uint16(len(ihm)))

	vec.InitialMessage = hex.EncodeToString(pkt.data)

	//sequetially choose sub-message from the first message
	for i, istate := range iStates {
		parsedPayload, rstate, cfg, msgIndex, err := ParseHandshake(kr, ihm, i, er)
		if err != nil {
			panic(err)
		}

		fmt.Println("chosen index", msgIndex)
		fmt.Printf("%s\n", cfg.Name)

		sess := &Session{
			Index:   msgIndex,
			Pattern: cfg.Pattern.Name,
			Dh:      cfg.DH.DHName(),
			Cipher:  cfg.Cipher.CipherName(),
			Hash:    cfg.Hash.HashName(),
		}
		vec.Sessions = append(vec.Sessions, sess)

		msg := &Message{}

		if len(parsedPayload) > 0 {

			fields, err := parseMessageFields(parsedPayload)
			if err != nil {
				panic(err)
			}

			flds := make(map[uint16]string)

			for _, v := range fields {
				flds[v.Type] = hex.EncodeToString(v.Data)
			}

			msg = &Message{
				Payload: hex.EncodeToString(parsedPayload),
				Fields:  flds,
			}

		}

		sess.HandshakeMessages = append(sess.HandshakeMessages, msg)

		pkt = InitializePacket() // 2 bytes for length

		if len(rstate.PeerStatic()) > 0 { //if we answer to IK, add one extra byte used for Noise pipes
			pkt.resize(len(pkt.data) + 2)
			pkt.data[len(pkt.data)-2] = msgIndex
		} else {
			pkt.resize(len(pkt.data) + 1)
			pkt.data[len(pkt.data)-1] = msgIndex
		}

		var cs1i, cs2i, cs1r, cs2r *noise.CipherState
		var hsm []byte
		payload := new(packet)
		payload.AddField(serverCert, MessageTypeCustomCert)

		hsm, cs1r, cs2r = rstate.WriteMessage(nil, payload.data)
		pkt.data = append(pkt.data, hsm...)
		binary.BigEndian.PutUint16(pkt.data, uint16(len(pkt.data)-2))

		msg = &Message{
			Ciphertext: hex.EncodeToString(pkt.data),
		}
		sess.HandshakeMessages = append(sess.HandshakeMessages, msg)
		sender := rstate
		receiver := istate

		for {

			parsedPayload, cs1i, cs2i, err = receiver.ReadMessage(nil, hsm)

			if err != nil {
				panic(err)
			}

			if len(parsedPayload) > 0 {
				msg.Payload = hex.EncodeToString(parsedPayload)
				fields, err := parseMessageFields(parsedPayload)
				if err != nil {
					panic(err)
				}
				flds := make(map[uint16]string)

				for _, v := range fields {
					flds[v.Type] = hex.EncodeToString(v.Data)
				}
				msg.Fields = flds
				//sess.HandshakeMessages = append(sess.HandshakeMessages, msg)
			}

			if cs1r != nil && cs2r != nil && cs1i != nil && cs2i != nil {
				fmt.Println(len(sess.HandshakeMessages))
				sess.HandshakeHash = hex.EncodeToString(receiver.ChannelBinding())
				fmt.Println("Transport messages GO")
				for j := 0; j < 2; j++ {
					di := make([]byte, 11)
					dr := make([]byte, 13)

					rand.Read(di)
					rand.Read(dr)

					pkti := InitializePacket()
					pkti.AddField(di, MessageTypeData)
					pkti.AddPadding(10)

					pktr := InitializePacket()
					pktr.AddField(dr, MessageTypeData)
					pktr.AddPadding(10)

					pktr.data = cs2r.Encrypt(pktr.data[:2], nil, pktr.data[2:])
					binary.BigEndian.PutUint16(pktr.data, uint16(len(pktr.data)-2))

					//fmt.Println(hex.EncodeToString(pktr.data))
					di, err = cs2i.Decrypt(pktr.data[:0], nil, pktr.data[2:])
					if err != nil {
						panic(err)
					}

					fields, err := parseMessageFields(di)
					for _, f := range fields {
						fmt.Println(f.Type, hex.EncodeToString(f.Data))
					}

					pkti.data = cs1i.Encrypt(pkti.data[:2], nil, pkti.data[2:])
					binary.BigEndian.PutUint16(pkti.data, uint16(len(pkti.data)-2))

					//fmt.Println(hex.EncodeToString(pkti.data))

					dr, err = cs1r.Decrypt(pkti.data[:0], nil, pkti.data[2:])
					if err != nil {
						panic(err)
					}
					fields, err = parseMessageFields(dr)
					for _, f := range fields {
						fmt.Println(f.Type, hex.EncodeToString(f.Data))
					}

				}

				fmt.Println()
				fmt.Println()
				break

			} else {
				sender, receiver = receiver, sender

				pkt = InitializePacket() // 2 bytes for length

				payload = new(packet)
				payload.AddField(clientCert, MessageTypeCustomCert)

				hsm, cs1r, cs2r = sender.WriteMessage(nil, payload.data)
				pkt.data = append(pkt.data, hsm...)
				binary.BigEndian.PutUint16(pkt.data, uint16(len(pkt.data)-2))
				msg = &Message{
					Ciphertext: hex.EncodeToString(pkt.data),
				}
				sess.HandshakeMessages = append(sess.HandshakeMessages, msg)

			}

		}
	}
	v, _ := json.Marshal(vec)
	fmt.Printf("%s\n", v)

}

func InitializePacket() *packet {
	block := new(packet)
	block.resize(uint16Size)
	return block
}
