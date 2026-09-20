package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	ps4tls "ps4-proxy/tls"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	switch os.Args[1] {
	case "gen-cert":
		flags := flag.NewFlagSet("gen-cert", flag.ExitOnError)
		cert := flags.String("cert", "cert.pem", "certificate output path")
		key := flags.String("key", "key.pem", "private key output path")
		flags.Parse(os.Args[2:])
		mainGenCert(*cert, *key)

	case "proxy":
		flags := flag.NewFlagSet("proxy", flag.ExitOnError)
		cert := flags.String("cert", "cert.pem", "certificate path")
		key := flags.String("key", "key.pem", "private key path")
		flags.Parse(os.Args[2:])
		mainProxy(*cert, *key)

	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", os.Args[1])
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ps4-proxy <gen-cert|proxy> [flags]")
	fmt.Fprintln(os.Stderr, "  gen-cert [--cert path] [--key path]")
	fmt.Fprintln(os.Stderr, "  proxy [--cert path] [--key path]")
	os.Exit(2)
}

func mainGenCert(certFilename, keyFilename string) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate private key: %v\n", err)
		return
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate serial number: %v\n", err)
		return
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "PS4 Proxy CA"},
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create certificate: %v\n", err)
		return
	}

	certFile, err := os.OpenFile(certFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open certificate file: %v\n", err)
		return
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		certFile.Close()
		fmt.Fprintf(os.Stderr, "write certificate: %v\n", err)
		return
	}
	if err := certFile.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "close certificate file: %v\n", err)
		return
	}

	keyFile, err := os.OpenFile(keyFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open private key file: %v\n", err)
		return
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		keyFile.Close()
		fmt.Fprintf(os.Stderr, "write private key: %v\n", err)
		return
	}
	if err := keyFile.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "close private key file: %v\n", err)
	}
}

func mainProxy(certFilename, keyFilename string) {
	ca, caKey, err := loadCert(certFilename, keyFilename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "loadCert: %v\n", err)
		return
	}

	keyLogWriter, err := os.OpenFile("keylog.txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open keylog: %v\n", err)
		return
	}

	for _, port := range []int{443} {
		ln, err := startProxyListener(ca, caKey, port, keyLogWriter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "listen: port=%d %s\n", port, err)
			return
		}
		go runProxy(ln, port, keyLogWriter)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	os.Exit(0)
}

func loadCert(certFilename, keyFilename string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certFilename)
	if err != nil {
		return nil, nil, fmt.Errorf("read certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFilename)
	if err != nil {
		return nil, nil, fmt.Errorf("read private key: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || keyBlock == nil {
		return nil, nil, fmt.Errorf("invalid certificate or private key PEM")
	}
	ca, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse private key: %w", err)
	}
	return ca, caKey, nil
}

func makeCert(ca *x509.Certificate, caKey *rsa.PrivateKey, host string) tls.Certificate {
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

func startProxyListener(ca *x509.Certificate, caKey *rsa.PrivateKey, port int, keyLogWriter io.Writer) (net.Listener, error) {
	ln, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert := makeCert(ca, caKey, chi.ServerName)
			return &cert, nil
		},
		KeyLogWriter: keyLogWriter,
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err != nil {
		return nil, fmt.Errorf("listen: %w\n", err)
	}
	fmt.Printf("Listening %s\n", ln.Addr())
	return ln, nil
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
	upstream, err := ps4tls.Dial("tcp", fmt.Sprintf("%s:%d", address, port), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial %s: %s", host, err)
		return
	}

	defer upstream.Close()
	go io.Copy(upstream, client)
	io.Copy(client, upstream)
}
