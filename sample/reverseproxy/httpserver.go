package main

import (
	"net/http"

	"os"

	"fmt"

	"time"

	"io/ioutil"

	"reflect"

	"crypto/rand"

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
	if r.TLS != nil {
		fmt.Println(r.TLS.TLSUnique)
	}
	w.Write(page)
}

func startNoiseSocketServer() {

	server := &http.Server{
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	router := httprouter.New()
	router.GET("/", Index)
	router.GET("/status", Status)

	server.Handler = router

	serverKeys := noise.DH25519.GenerateKeypair(rand.Reader)

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

func Status(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {

	//get underlying connection via reflection
	val := reflect.ValueOf(w)
	val = reflect.Indirect(val)

	// w is a "http.response" struct from which we get the 'conn' field
	val = val.FieldByName("conn")
	val = reflect.Indirect(val)

	// which is a http.conn from which we get the 'rwc' field
	val = val.FieldByName("rwc").Elem().Elem()

	infoLen := val.FieldByName("connectionInfo").Len()
	info := val.FieldByName("connectionInfo").Slice(0, infoLen)

	w.Write(info.Bytes())
}
