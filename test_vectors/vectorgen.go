package main

import (
	"crypto/rand"

	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/flynn/noise"
	"gopkg.in/noisesocket.v0"
)

type TestVector struct {
	Name string `json:"name"`
}

func main() {
	ki := noise.DH25519.GenerateKeypair(rand.Reader)
	ks := noise.DH25519.GenerateKeypair(rand.Reader)

	payload := make([]byte, 4)
	binary.BigEndian.PutUint16(payload, 2) // whole payload is just a zero length padding field

	ihm, prologue, iStates, err := noisesocket.ComposeInitiatorHandshakeMessages(ki, ks.Public, payload)
	if err != nil {
		panic(err)
	}

	fmt.Println("1st message", hex.EncodeToString(ihm))
	fmt.Println("prologue", hex.EncodeToString(prologue))

	for i, istate := range iStates {
		parsedPayload, rstate, msgIndex, err := noisesocket.ParseHandshake(ks, ihm, i)

		if err != nil {
			panic(err)
		}

		fmt.Println("chosen index", msgIndex)
		fmt.Println("payload from the first message", hex.EncodeToString(parsedPayload))

		sender := rstate
		receiver := istate

		for {
			var cs1i, cs2i, cs1r, cs2r *noise.CipherState

			msg, cs1r, cs2r := sender.WriteMessage(nil, nil)
			fmt.Println("handhake messsage", hex.EncodeToString(msg))
			_, cs1i, cs2i, err = receiver.ReadMessage(nil, msg)

			if err != nil {
				panic(err)
			}
			if cs1r != nil && cs2r != nil && cs1i != nil && cs2i != nil {
				fmt.Println("Transport messages GO")
				for j := 0; j < 2; j++ {
					di := make([]byte, 10)
					dr := make([]byte, 10)

					rand.Read(di)
					rand.Read(dr)

					fmt.Println(hex.EncodeToString(di))
					msg := cs1i.Encrypt(nil, nil, di)
					fmt.Println(hex.EncodeToString(msg))
					dr, err = cs1r.Decrypt(nil, nil, msg)
					if err != nil {
						panic(err)
					}
					fmt.Println(hex.EncodeToString(dr))
					msg = cs2r.Encrypt(nil, nil, dr)
					fmt.Println(hex.EncodeToString(msg))
					di, err = cs2i.Decrypt(nil, nil, msg)
					if err != nil {
						panic(err)
					}
				}

				fmt.Println()
				fmt.Println()
				break

			} else {
				sender, receiver = receiver, sender
			}

		}
	}

}
