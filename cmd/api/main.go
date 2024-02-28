package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	// "github.com/gorilla/mux"
)

type Handler struct {} 

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r)
	w.WriteHeader(403)
}

func main() {	
	// h := &Handler{}
	// log.Fatal(http.ListenAndServe(":8000", h))
	cConfig := new(tls.Config)
	cConfig.MinVersion = tls.VersionTLS11
	cConfig.MaxVersion = tls.VersionTLS11
	cConfig.KeyLogWriter = os.Stdout
	cConfig.InsecureSkipVerify = true
	// cConfig.ServerName = chi.ServerName
	sconn, err := tls.Dial("tcp", "mail.ru:443", cConfig)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer sconn.Close()
}