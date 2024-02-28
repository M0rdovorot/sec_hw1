package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"path/filepath"

	"github.com/M0rdovorot/sec_hw1/internal/proxy"
	// "github.com/gorilla/mux"
)

var (
	keyFile  = filepath.Join("certs", "ca.key")
	certFile = filepath.Join("certs", "ca.crt")
)

func loadCA() (cert tls.Certificate, err error) {
	cert, err = tls.LoadX509KeyPair(certFile, keyFile)
	if err == nil {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	}
	return
}

func main() {
	ca, err := loadCA()
	if err != nil {
		fmt.Println("???/")
		log.Fatal(err)
	}

	p := &proxy.Proxy{
		Handler: &httputil.ReverseProxy{
			Director: func(r *http.Request) {
				r.Header.Del("Proxy-Connection")
				fmt.Println(r)
				// r.URL = &url.URL{
				// 	Scheme: "http",
				// 	Path: "/",
				// 	Host: "mail.ru",
				// }
				// fmt.Println(r.)
				
			},
		},
		CA: &ca,
	}

	log.Fatal(http.ListenAndServe(":8080", p))
	// log.Fatal(http.ListenAndServeTLS(":8080","certs/ca.crt","certs/ca.key", p))
}