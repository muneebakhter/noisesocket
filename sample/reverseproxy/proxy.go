package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"

	"log"

	"net/http/httputil"
	"net/url"

	"crypto/rand"

	"github.com/flynn/noise"
	"gopkg.in/noisesocket.v0"
)
import "github.com/oxtoacart/bpool"

var (
	serverPub  []byte
	clientKeys noise.DHKey
)

func main() {

	backendUrl, _ := url.Parse("https://localhost:13242")
	reverseProxy := httputil.NewSingleHostReverseProxy(backendUrl)

	transport := &http.Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			return noisesocket.Dial(network, addr, clientKeys, serverPub, nil, nil)
		},
	}

	reverseProxy.Transport = transport
	reverseProxy.BufferPool = bpool.NewBytePool(10, 32*10124)
	fmt.Println("Reverse proxy server is listening on port 1080. Try http://localhost:1080")
	log.Fatal(http.ListenAndServe(":1080", reverseProxy))

}

func init() {
	serverPub, _ = base64.StdEncoding.DecodeString("J6TRfRXR5skWt6w5cFyaBxX8LPeIVxboZTLXTMhk4HM=")
	clientKeys = noise.DH25519.GenerateKeypair(rand.Reader)
}
