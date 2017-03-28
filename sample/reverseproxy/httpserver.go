package main

import (
	"net/http"

	"os"

	"fmt"

	"encoding/base64"

	"time"

	"io/ioutil"

	"github.com/flynn/noise"
	"github.com/julienschmidt/httprouter"
	"gopkg.in/noisesocket.v0"
)

func main() {

	startNoiseSocketServer()

}

var page []byte

func init() {
	var err error
	page, err = ioutil.ReadFile("index.html")
	if err != nil {
		panic(err)
	}

}

func Index(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

	w.Write(page)
}

func startNoiseSocketServer() {
	server := &http.Server{
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
	}

	router := httprouter.New()
	router.GET("/", Index)

	server.Handler = router

	pub, _ := base64.StdEncoding.DecodeString("J6TRfRXR5skWt6w5cFyaBxX8LPeIVxboZTLXTMhk4HM=")
	priv, _ := base64.StdEncoding.DecodeString("vFilCT/FcyeShgbpTUrpru9n5yzZey8yfhsAx6DeL80=")

	serverKeys := noise.DHKey{
		Public:  pub,
		Private: priv,
	}

	l, err := noisesocket.Listen("tcp", ":13242", serverKeys, nil, nil)
	if err != nil {
		fmt.Println("Error listening:", err)
		os.Exit(1)
	}

	fmt.Println("Noise http server is listening on port 13242")
	if err := server.Serve(l); err != nil {
		panic(err)
	}
}
