package main

import (
	"crypto/rand"
	"fmt"
	"net"
	"net/http"

	"github.com/flynn/noise"

	"bytes"
	"io"
	"io/ioutil"

	"github.com/namsral/flag"
	"gopkg.in/noisesocket.v0"
	"gopkg.in/noisesocket.v0/sample/virgil/helpers"
)

func main() {
	flag.Parse()
	api := helpers.GetApi()
	instanceKey := noise.DH25519.GenerateKeypair(rand.Reader)

	card, cardKey := helpers.GenerateAppSignedCard(api)

	payload := helpers.MakePayload(instanceKey.Public, card, cardKey)

	validatefunc := helpers.Validate(api)

	transport := makeTransport(instanceKey, nil, payload, validatefunc)

	buf := make([]byte, 1024)
	cli := &http.Client{Transport: transport}
	for i := 1; i < 100; i++ {
		makeRequest(cli, buf)
		fmt.Println(i)
	}

}

func makeRequest(cli *http.Client, buf []byte) {

	reader := bytes.NewReader(buf)
	req, err := http.NewRequest("POST", "https://127.0.0.1:12888/", reader)
	if err != nil {
		panic(err)
	}

	resp, err := cli.Do(req)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	_, err = io.Copy(ioutil.Discard, resp.Body)
	if err != nil {
		panic(err)
	}
	err = resp.Body.Close()
	if err != nil {
		panic(err)
	}

}

func makeTransport(instanceKey noise.DHKey, serverPub []byte, payload []*noisesocket.Field, callbackFunc noisesocket.VerifyCallbackFunc) *http.Transport {

	return &http.Transport{
		MaxIdleConnsPerHost: 10,
		DialTLS: func(network, addr string) (net.Conn, error) {
			conn, err := noisesocket.Dial(network, addr, instanceKey, serverPub, payload, callbackFunc, 0)
			if err != nil {
				fmt.Println("Dial", err)
			}

			return conn, err
		},
	}
}
