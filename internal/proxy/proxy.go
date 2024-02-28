package proxy

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"os/exec"
	"strings"
)

const (
	tmplScript = `openssl req -new -key certs/cert.key -subj "/CN=$1" -sha256 | openssl x509 -req -days 3650 -CA certs/ca.crt -CAkey certs/ca.key -set_serial "$2"`
)

type Proxy struct {
	http.Handler
	
	CA *tls.Certificate
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r)
	if r.Method == "CONNECT" {
		p.serveConnect(w, r)
		return
	}
	wr := httptest.NewRecorder()
	p.Handler.ServeHTTP(wr, r)
	w.WriteHeader(wr.Code)
	io.Copy(w, wr.Body)
	for header, valueArray := range wr.Header() {
		for _, value := range valueArray {
			w.Header().Set(header, value)
		}
	}
	fmt.Println(w)

	// p.Handler.ServeHTTP(w, r)
	// fmt.Println(w)
}

func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	// w.WriteHeader(200)

	var sconn *tls.Conn

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Println(fmt.Errorf("failed to generate serial number: %s", err))
		http.Error(w, "no upstream", 503)
		return
	}

	host, _, _ := net.SplitHostPort(r.Host)
	// fmt.Println(host)

	replacer := strings.NewReplacer("$1", host, "$2", serialNumber.String())
	// replacer := strings.NewReplacer("$1", host)
	script := replacer.Replace(tmplScript)

	// out, err := exec.Command(script).Output()
	err = os.WriteFile("script.sh", []byte(script), os.ModePerm)
	if err != nil {
		log.Println(fmt.Errorf("failed to save file: %s", err))
		return
	}

	cmd := exec.Command("/bin/sh", "script.sh")
	cmd.Dir = ""
	// fmt.Println(cmd.String())
	out, err := cmd.Output()
	if err != nil {
		log.Println(fmt.Errorf("failed to execute: %s", err))
		http.Error(w, "no upstream", 503)
		return
	}
	// fmt.Println(string(out), script)

	err = os.WriteFile("host.crt", []byte(out), os.ModePerm)
	if err != nil {
		log.Println(fmt.Errorf("failed to save file: %s", err))
		return
	}
	
	cert, err := tls.LoadX509KeyPair("host.crt", "certs/cert.key")
	if err == nil {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			log.Println("smth wrong:", err)
			return
		}
	}
	// roots := x509.NewCertPool()
	// ok :=roots.AppendCertsFromPEM(out)
	// if !ok {
	// 	log.Println("problem")
	// 	return
	// }


	sConfig := new(tls.Config)
	sConfig.Certificates = []tls.Certificate{cert}
	// sConfig.RootCAs = roots
	sConfig.MinVersion = tls.VersionTLS12
	sConfig.MaxVersion = tls.VersionTLS12
	sConfig.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cConfig := new(tls.Config)
		cConfig.MinVersion = tls.VersionTLS12
		cConfig.MaxVersion = tls.VersionTLS12
		cConfig.ServerName = chi.ServerName
		sconn, err = tls.Dial("tcp", r.Host, cConfig)
		if err != nil {
			log.Println("dial", r.Host, err)
			return nil, err
		}
		// fmt.Println("?)")
		var host_cert tls.Certificate
		{
			serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
			serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
			if err != nil {
				log.Println(fmt.Errorf("failed to generate serial number: %s", err))
				http.Error(w, "no upstream", 503)
				// return
			}

			replacer := strings.NewReplacer("$1", chi.ServerName, "$2", serialNumber.String())
			// replacer := strings.NewReplacer("$1", host)
			script := replacer.Replace(tmplScript)
		
			// out, err := exec.Command(script).Output()
			err = os.WriteFile("script.sh", []byte(script), os.ModePerm)
			if err != nil {
				log.Println(fmt.Errorf("failed to save file: %s", err))
				// return
			}
		
			cmd := exec.Command("/bin/sh", "script.sh")
			cmd.Dir = ""
			// fmt.Println(cmd.String())
			out, err := cmd.Output()
			if err != nil {
				log.Println(fmt.Errorf("failed to execute: %s", err))
				http.Error(w, "no upstream", 503)
				// return
			}
			// fmt.Println(string(out), script)
		
			err = os.WriteFile("host.crt", []byte(out), os.ModePerm)
			if err != nil {
				log.Println(fmt.Errorf("failed to save file: %s", err))
				// return
			}
			
			host_cert, err = tls.LoadX509KeyPair("host.crt", "certs/cert.key")
			if err == nil {
				host_cert.Leaf, err = x509.ParseCertificate(host_cert.Certificate[0])
				if err != nil {
					log.Println("smth wrong:", err)
					// return
				}
			}
		}


		// return &cert, nil
		// return p.CA, nil
		return &host_cert, nil
	}
	cconn, err := handshake(w, sConfig)
	if err != nil {
		log.Println("handshake", r.Host, err)
		return
	}
	defer cconn.Close()
	
	// cConfig := new(tls.Config)
	// cConfig.ServerName = 
	// sconn, err := tls.Dial("tcp", r.Host, cConfig)
	// if err != nil {
	// 	log.Println("dial", r.Host, err)
	// 	return 
	// }
	if sconn == nil {
		log.Println("could not determine cert name for " + r.Host)
		return
	}
	defer sconn.Close()

	rp := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Host = r.Host
			r.URL.Scheme = "https"
		},
		Transport: &http.Transport{DialTLS: func(network, addr string) (net.Conn, error) {
			return sconn, nil
		}},
	}
	http.Serve(&oneShotListener{cconn}, rp)


	// var (
	// 	err   error
	// 	sconn *tls.Conn
	// 	name  = dnsName(r.Host)
	// )

	// if name == "" {
	// 	log.Println("cannot determine cert name for " + r.Host)
	// 	http.Error(w, "no upstream", 503)
	// 	return
	// }


}

type oneShotListener struct {
	c net.Conn
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.c == nil {
		return nil, errors.New("closed")
	}
	c := l.c
	l.c = nil
	return c, nil
}

func (l *oneShotListener) Close() error {
	return nil
}

func (l *oneShotListener) Addr() net.Addr {
	return l.c.LocalAddr()
}

func handshake(w http.ResponseWriter, config *tls.Config) (net.Conn, error) {
	raw, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, "no upstream", 503)
		return nil, err
	}
	if _, err = raw.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		log.Println(err)
		raw.Close()
		return nil, err
	}
	conn := tls.Server(raw, config)
	err = conn.Handshake()
	if err != nil {
		fmt.Println("))", err)
		conn.Close()
		raw.Close()
		return nil, err
	}
	return conn, nil
}