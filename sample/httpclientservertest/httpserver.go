package main

import (
	"net/http"

	"os"

	"crypto/rand"

	"fmt"

	"flag"

	"encoding/base64"
	"io"
	"io/ioutil"

	"time"

	"github.com/flynn/noise"
	"gopkg.in/noisesocket.v0"
)

var (
	listen = flag.String("listen", ":5000", "Port to listen on")
)

func main() {

	//go startHttpServer()
	startNoiseSocketServer()

}

func startNoiseSocketServer() {
	server := &http.Server{
		Addr:         *listen,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
	}
	server.SetKeepAlivesEnabled(false)

	buf := make([]byte, 2048*2+17) //send 4113 bytes
	rand.Read(buf)
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(ioutil.Discard, r.Body)
		r.Body.Close()
		w.Write(buf)
	})

	pub, _ := base64.StdEncoding.DecodeString("J6TRfRXR5skWt6w5cFyaBxX8LPeIVxboZTLXTMhk4HM=")
	priv, _ := base64.StdEncoding.DecodeString("vFilCT/FcyeShgbpTUrpru9n5yzZey8yfhsAx6DeL80=")

	serverKeys := noise.DHKey{
		Public:  pub,
		Private: priv,
	}

	payloadData := make([]byte, 2048)
	rand.Read(payloadData)

	payload := []*noisesocket.Field{
		{
			Data: payloadData,
			Type: noisesocket.MessageTypeCustomCert,
		},
		{
			Data: payloadData,
			Type: noisesocket.MessageTypeSignature,
		},
	}

	l, err := noisesocket.Listen("tcp", ":12888", serverKeys, payload, nil, -1)
	if err != nil {
		fmt.Println("Error listening:", err)
		os.Exit(1)
	}

	fmt.Println("Starting server...")
	if err := server.Serve(l); err != nil {
		panic(err)
	}
}
