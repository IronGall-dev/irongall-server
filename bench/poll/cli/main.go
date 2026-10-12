package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
)

func main() {
	n, _ := strconv.Atoi(os.Args[1])
	H := make([]byte, 32)
	H[0] = 9
	mac := hmac.New(sha256.New, make([]byte, 32))
	mac.Write([]byte("irongall-token-v1"))
	mac.Write(H)
	mac.Write([]byte{0, 0, 0, 0})
	tok := "Bearer igt1_" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	url := "http://127.0.0.1:18777/v1/" + hex.EncodeToString(H) + "/messages"
	tr := &http.Transport{MaxIdleConnsPerHost: 4}
	c := &http.Client{Transport: tr}
	var wg sync.WaitGroup
	bad := 0
	var mu sync.Mutex
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < n/4; i++ {
				req, _ := http.NewRequest("GET", url, nil)
				req.Header.Set("Authorization", tok)
				resp, err := c.Do(req)
				if err != nil {
					mu.Lock()
					bad++
					mu.Unlock()
					continue
				}
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != 200 || string(b) != "[]" {
					mu.Lock()
					bad++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	fmt.Println("requests", n, "bad", bad)
}
