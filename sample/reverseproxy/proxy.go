package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"

	"log"

	"io"

	"github.com/flynn/noise"
	"gopkg.in/noisesocket.v0"
)

func main() {

	pub1, _ := base64.StdEncoding.DecodeString("L9Xm5qy17ZZ6rBMd1Dsn5iZOyS7vUVhYK+zby1nJPEE=")
	priv1, _ := base64.StdEncoding.DecodeString("TPmwb3vTEgrA3oq6PoGEzH5hT91IDXGC9qEMc8ksRiw=")

	serverPub, _ := base64.StdEncoding.DecodeString("J6TRfRXR5skWt6w5cFyaBxX8LPeIVxboZTLXTMhk4HM=")

	clientKeys := noise.DHKey{
		Public:  pub1,
		Private: priv1,
	}

	transport := &http.Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			conn, err := noisesocket.Dial(network, addr, clientKeys, serverPub, nil, nil)
			if err != nil {
				fmt.Println("Dial", err)
			}

			return conn, err
		},
	}

	client := &http.Client{Transport: transport}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		send(w, r, client)
	})
	fmt.Println("Reverse proxy server is listening on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func send(w http.ResponseWriter, r *http.Request, client *http.Client) error {

	req, err := http.NewRequest("GET", "https://localhost:13242"+r.URL.Path, nil)
	if err != nil {
		log.Fatal(err)
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
		return err
	}
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Fatal(err)
		return err
	}
	defer resp.Body.Close()
	return nil
}
