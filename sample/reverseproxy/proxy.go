package main

import (
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
import (
	"encoding/base64"

	"github.com/oxtoacart/bpool"
)

var (
	serverPub []byte
)

func main() {

	backendUrl, _ := url.Parse("https://localhost:13242")
	reverseProxy := httputil.NewSingleHostReverseProxy(backendUrl)

	transport := &proxyTransport{
		Transport: http.Transport{
			DisableKeepAlives: true,
		},
	}

	transport.DialTLS = func(network, addr string) (net.Conn, error) {
		clientKeys := noise.DH25519.GenerateKeypair(rand.Reader)
		conn, err := noisesocket.Dial(network, addr, clientKeys, serverPub, nil, serverCallback)
		transport.conn = conn
		return conn, err

	}

	reverseProxy.Transport = transport
	reverseProxy.BufferPool = bpool.NewBytePool(10, 32*10124)
	fmt.Println("Reverse proxy server is listening on port 1080. Try http://localhost:1080")
	log.Fatal(http.ListenAndServe(":1080", reverseProxy))

}

type proxyTransport struct {
	http.Transport
	conn *noisesocket.Conn
}

//add headers with info from proxy

func (p *proxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := p.Transport.RoundTrip(req)
	resp.Header.Add("X-HANDSHAKE-HASH", base64.StdEncoding.EncodeToString(p.conn.ChannelBinding()))
	resp.Header.Add("X-PEER-KEY", base64.StdEncoding.EncodeToString(serverPub))
	return resp, err
}

//used to cache server's key
func serverCallback(publicKey []byte, _ []*noisesocket.Field) error {
	serverPub = publicKey
	return nil
}
