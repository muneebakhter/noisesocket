package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/flynn/noise"
	"github.com/namsral/flag"
	"gopkg.in/noisesocket.v0"
	"gopkg.in/noisesocket.v0/sample/virgil/helpers"
)

func main() {
	flag.Parse()
	serverKey := noise.DH25519.GenerateKeypair(rand.Reader)
	api := helpers.GetApi()
	verifyFunc := helpers.Validate(api)

	card, cardKey := helpers.GenerateAppSignedCard(api)
	payload := helpers.MakePayload(serverKey.Public, card, cardKey)

	startNoiseSocketServer(serverKey, payload, verifyFunc)
}

func startNoiseSocketServer(serverKeys noise.DHKey, payload []*noisesocket.Field, verifier noisesocket.VerifyCallbackFunc) {
	server := &http.Server{
		Addr:         ":2345",
		ReadTimeout:  1 * time.Hour,
		WriteTimeout: 1 * time.Hour,
	}

	buf := make([]byte, 2048*2+17) //send 4113 bytes
	rand.Read(buf)
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(ioutil.Discard, r.Body)
		r.Body.Close()
		w.Write(buf)
	})

	l, err := noisesocket.Listen("tcp", ":12888", serverKeys, payload, verifier)
	if err != nil {
		fmt.Println("Error listening:", err)
		os.Exit(1)
	}

	fmt.Println("Starting server...")
	if err := server.Serve(l); err != nil {
		panic(err)
	}
}
