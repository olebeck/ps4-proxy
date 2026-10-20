package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "embed"
	ps4tls "ps4-proxy/tls"
)

//go:embed EM_OV_TLS_CA_G3C.pem
var emCaPem []byte

//go:embed EM_OV_TLS_CA_G3C.key
var emKeyPem []byte

var emCa *x509.Certificate
var emKey *ecdsa.PrivateKey

func init() {
	var err error
	emCa, emKey, err = parseCert(emCaPem, emKeyPem)
	if err != nil {
		panic(err)
	}
}

func main() {
	ports := []int{443}
	keyLogWriter, err := os.OpenFile("keylog.txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open keylog: %v\n", err)
		return
	}

	getCertificate := func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert := makeCert(emCa, emKey, chi.ServerName)
		return &cert, nil
	}

	for _, port := range ports {
		ln, err := startProxyListener(port, getCertificate, keyLogWriter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "listen: port=%d %s\n", port, err)
			return
		}
		go runProxy(ln, port, keyLogWriter)
	}
	go runHttpProxy()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	os.Exit(0)
}

func parseCert(certPEM, keyPEM []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || keyBlock == nil {
		return nil, nil, fmt.Errorf("invalid certificate or private key PEM")
	}
	ca, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}
	caKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse private key: %w", err)
	}
	return ca, caKey, nil
}

func makeCert(ca *x509.Certificate, caKey *ecdsa.PrivateKey, host string) tls.Certificate {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: leafKey}
}

type certFunc func(chi *tls.ClientHelloInfo) (*tls.Certificate, error)

func startProxyListener(port int, getCertificate certFunc, keyLogWriter io.Writer) (net.Listener, error) {
	ln, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), &tls.Config{
		GetCertificate: getCertificate,
		KeyLogWriter:   keyLogWriter,
		NextProtos:     []string{"h2", "http/1.1"},
	})
	if err != nil {
		return nil, fmt.Errorf("listen: %w\n", err)
	}
	fmt.Printf("Listening %s\n", ln.Addr())
	return ln, nil
}

func runHttpProxy() {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = pr.In.Host
			pr.Out.Host = pr.In.Host
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy error for %s: %v", r.Host, err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
	ln, err := net.Listen("tcp4", "0.0.0.0:80")
	if err != nil {
		log.Fatalf("listen: %s", err)
	}
	defer ln.Close()
	fmt.Printf("Listening %s\n", ln.Addr())
	log.Fatal(http.Serve(ln, proxy))
}

func runProxy(ln net.Listener, port int, keyLogWriter io.Writer) {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "accept %s: %s\n", ln.Addr(), err)
			return
		}
		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			fmt.Fprintf(os.Stderr, "handshake %s: %s\n", ln.Addr(), err)
			return
		}
		state := tlsConn.ConnectionState()
		fmt.Printf("Connect %s\n", state.ServerName)
		go proxyConnection(conn, state.ServerName, port, keyLogWriter)
	}
}

func resolveHost(host string) (string, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", "1.1.1.1:53")
		},
	}
	addresses, err := resolver.LookupHost(context.Background(), host)
	if err != nil {
		return "", err
	}
	if len(addresses) == 0 {
		return "", fmt.Errorf("no addresses found for %q", host)
	}
	return addresses[0], nil
}

var ps4TlsConfig = &ps4tls.Config{
	InsecureSkipVerify: true,
	CipherSuites: []uint16{
		ps4tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		ps4tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		ps4tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		ps4tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		ps4tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		ps4tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		ps4tls.TLS_RSA_WITH_AES_256_CBC_SHA256,
		ps4tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		ps4tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		ps4tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		ps4tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		ps4tls.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
	},
	MinVersion: ps4tls.VersionTLS12,
	MaxVersion: ps4tls.VersionTLS12,
	NextProtos: []string{"h2", "http/1.1"},
}

func proxyConnection(client net.Conn, host string, port int, keyLogWriter io.Writer) {
	defer client.Close()
	address, err := resolveHost(host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve %s: %s", host, err)
		return
	}
	fmt.Printf("dial %s\n", address)

	cfg := ps4TlsConfig.Clone()
	cfg.ServerName = host
	cfg.KeyLogWriter = keyLogWriter
	upstream, err := ps4tls.Dial("tcp", fmt.Sprintf("%s:%d", host, port), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial %s: %s", host, err)
		return
	}

	defer upstream.Close()
	go io.Copy(upstream, client)
	io.Copy(client, upstream)
}
