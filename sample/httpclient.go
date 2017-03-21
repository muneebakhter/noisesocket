package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"sort"
	"sync"

	"github.com/flynn/noise"
	"gopkg.in/noisesocket.v0"
)

func main() {

	t := time.Now()
	n := 10000
	buf := make([]byte, 55)
	rand.Read(buf)

	threads := 5

	c := make(chan bool, threads)

	pub1, _ := base64.StdEncoding.DecodeString("L9Xm5qy17ZZ6rBMd1Dsn5iZOyS7vUVhYK+zby1nJPEE=")
	priv1, _ := base64.StdEncoding.DecodeString("TPmwb3vTEgrA3oq6PoGEzH5hT91IDXGC9qEMc8ksRiw=")

	serverPub, _ := base64.StdEncoding.DecodeString("J6TRfRXR5skWt6w5cFyaBxX8LPeIVxboZTLXTMhk4HM=")

	clientKeys := noise.DHKey{
		Public:  pub1,
		Private: priv1,
	}

	payload := []byte(`{json:yes}111`)
	stats := make(map[int]int)

	transport := &http.Transport{
		MaxIdleConnsPerHost: 1,
		DisableKeepAlives:   true,
		DialTLS: func(network, addr string) (net.Conn, error) {
			conn, err := noisesocket.Dial(network, addr, clientKeys, serverPub, payload)
			if err != nil {
				fmt.Println("Dial", err)
			}

			return conn, err
		},
	}

	mu := sync.Mutex{}
	go func(stats map[int]int) {

		for {
			mu.Lock()
			var keys []int
			for k := range stats {
				keys = append(keys, k)
			}
			sort.Ints(keys)

			// To perform the opertion you want
			for _, k := range keys {
				fmt.Printf("%d:%d ", k, stats[k])
			}
			fmt.Println()
			mu.Unlock()
			time.Sleep(time.Second * 2)
		}
	}(stats)

	for j := 0; j < threads; j++ {
		go func(t int) {

			for i := 0; i < n; i++ {
				reader := bytes.NewReader(buf)
				req, err := http.NewRequest("POST", "https://127.0.0.1:12888/", reader)
				if err != nil {
					panic(err)
				}
				cli := &http.Client{
					Transport: transport,
				}
				resp, err := cli.Do(req)
				if err != nil {
					fmt.Println(err)
					continue
				}
				_, err = io.Copy(ioutil.Discard, resp.Body)
				if err != nil {
					panic(err)
				}
				err = resp.Body.Close()
				if err != nil {
					panic(err)
				}
				mu.Lock()
				stats[t] = i
				mu.Unlock()
			}
			fmt.Println("donedone", t)
			c <- true
		}(j)
	}

	for j := 0; j < threads; j++ {
		<-c
	}
	fmt.Println(time.Since(t).Seconds())
}
