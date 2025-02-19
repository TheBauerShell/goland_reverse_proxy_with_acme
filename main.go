// main.go
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
	
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)

// ACME-Konfigurationsstruktur
type ACMEConfig struct {
	Email         string `json:"email"`
	DirectoryURL  string `json:"directory_url"`
	StoragePath   string `json:"storage_path"`
	DNSProvider   string `json:"dns_provider"`
	RenewBefore   int    `json:"renew_before"`
	PrivateKey    string `json:"-"`
}

// Domain-Konfiguration
type DomainConfig struct {
	Domain      string `json:"domain"`
	Backend     string `json:"backend"`
	Certificate struct {
		CertPath string `json:"cert_path"`
		KeyPath  string `json:"key_path"`
	} `json:"certificate"`
}

// Gesamtkonfiguration
type Config struct {
	ACME   ACMEConfig     `json:"acme"`
	Domains []DomainConfig `json:"domains"`
	mu     sync.RWMutex
}

// User-Implementierung für ACME
type ACMEUser struct {
	Email        string
	Registration *registration.Resource
	PrivateKey   []byte
}

func (u *ACMEUser) GetEmail() string {
	return u.Email
}

func (u *ACMEUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *ACMEUser) GetPrivateKey() []byte {
	return u.PrivateKey
}

// Reverse-Proxy-Handler
type ReverseProxy struct {
	config    *Config
	client    *lego.Client
	transport *http.Transport
	certCache map[string]*tls.Certificate
	cacheLock sync.RWMutex
}

func NewReverseProxy(cfg *Config) *ReverseProxy {
	return &ReverseProxy{
		config:    cfg,
		transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		certCache: make(map[string]*tls.Certificate),
	}
}

// ACME-Client initialisieren
func (rp *ReverseProxy) initACMEClient() error {
	user := &ACMEUser{
		Email: rp.config.ACME.Email,
	}

	config := lego.NewConfig(user)
	config.CADirURL = rp.config.ACME.DirectoryURL

	client, err := lego.NewClient(config)
	if err != nil {
		return fmt.Errorf("ACME client init fehlgeschlagen: %w", err)
	}

	// DNS-Provider konfigurieren
	switch rp.config.ACME.DNSProvider {
	case "cloudflare":
		cfProvider, err := cloudflare.NewDefaultProvider()
		if err != nil {
			return fmt.Errorf("Cloudflare-Provider fehlgeschlagen: %w", err)
		}
		err = client.Challenge.SetDNS01Provider(cfProvider,
			dns01.DisableCompletePropagationRequirement(),
		)
	default:
		return fmt.Errorf("nicht unterstützter DNS-Provider: %s", rp.config.ACME.DNSProvider)
	}

	rp.client = client
	return nil
}

// Zertifikat erstellen/erneuern
func (rp *ReverseProxy) ensureCertificate(domain string) error {
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	cert, err := rp.client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("Zertifikatsbeschaffung fehlgeschlagen: %w", err)
	}

	rp.config.mu.Lock()
	defer rp.config.mu.Unlock()

	for i := range rp.config.Domains {
		if rp.config.Domains[i].Domain == domain {
			certPath := filepath.Join(rp.config.ACME.StoragePath, domain+".crt")
			keyPath := filepath.Join(rp.config.ACME.StoragePath, domain+".key")

			if err := os.WriteFile(certPath, cert.Certificate, 0600); err != nil {
				return fmt.Errorf("Zertifikatspeicherung fehlgeschlagen: %w", err)
			}

			if err := os.WriteFile(keyPath, cert.PrivateKey, 0600); err != nil {
				return fmt.Errorf("Schlüsselspeicherung fehlgeschlagen: %w", err)
			}

			rp.config.Domains[i].Certificate.CertPath = certPath
			rp.config.Domains[i].Certificate.KeyPath = keyPath
			return nil
		}
	}

	return fmt.Errorf("Domain nicht in Konfiguration gefunden: %s", domain)
}

// Proxy-Handler
func (rp *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rp.config.mu.RLock()
	defer rp.config.mu.RUnlock()

	host := r.Host
	for _, domain := range rp.config.Domains {
		if domain.Domain == host {
			target, _ := url.Parse(domain.Backend)
			proxy := httputil.NewSingleHostReverseProxy(target)
			proxy.Transport = rp.transport

			// TLS-Konfiguration setzen
			tlsConfig := &tls.Config{
				GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					return rp.getCertificate(hello.ServerName)
				},
			}

			if r.TLS == nil {
				// HTTPS-Umleitung
				http.Redirect(w, r, "https://"+host+r.RequestURI, http.StatusMovedPermanently)
				return
			}

			proxy.ServeHTTP(w, r)
			return
		}
	}

	http.Error(w, "Domain nicht konfiguriert", http.StatusBadGateway)
}

// Zertifikatsverwaltung
func (rp *ReverseProxy) getCertificate(domain string) (*tls.Certificate, error) {
	rp.cacheLock.RLock()
	cert, exists := rp.certCache[domain]
	rp.cacheLock.RUnlock()

	if exists {
		return cert, nil
	}

	rp.config.mu.RLock()
	defer rp.config.mu.RUnlock()

	for _, d := range rp.config.Domains {
		if d.Domain == domain {
			cert, err := tls.LoadX509KeyPair(d.Certificate.CertPath, d.Certificate.KeyPath)
			if err != nil {
				return nil, fmt.Errorf("Zertifikatsladung fehlgeschlagen: %w", err)
			}

			rp.cacheLock.Lock()
			rp.certCache[domain] = &cert
			rp.cacheLock.Unlock()

			return &cert, nil
		}
	}

	return nil, fmt.Errorf("kein Zertifikat für Domain gefunden: %s", domain)
}

// Admin-Webinterface
func startAdminInterface(config *Config) {
	http.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		config.mu.RLock()
		defer config.mu.RUnlock()

		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(config)
			return
		}

		if r.Method == http.MethodPost {
			var newConfig Config
			if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			config.mu.Lock()
			*config = newConfig
			config.mu.Unlock()

			if err := saveConfig(config); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusAccepted)
		}
	})

	log.Println("Admin-Interface läuft auf :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// Konfigurationsspeicherung
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Konfigurationslesefehler: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("Konfigurationsparsing fehlgeschlagen: %w", err)
	}

	return &config, nil
}

func saveConfig(config *Config) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("Konfigurationsserialisierung fehlgeschlagen: %w", err)
	}

	return os.WriteFile("config.json", data, 0600)
}

func main() {
	// Konfiguration laden
	config, err := loadConfig("config.json")
	if err != nil {
		log.Fatalf("Konfigurationsfehler: %v", err)
	}

	// Reverse Proxy initialisieren
	proxy := NewReverseProxy(config)
	if err := proxy.initACMEClient(); err != nil {
		log.Fatalf("ACME-Initialisierungsfehler: %v", err)
	}

	// Zertifikate überprüfen und erneuern
	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		for range ticker.C {
			for _, domain := range config.Domains {
				if err := proxy.ensureCertificate(domain.Domain); err != nil {
					log.Printf("Zertifikatserneuerungsfehler für %s: %v", domain.Domain, err)
				}
			}
		}
	}()

	// HTTP->HTTPS Redirect Server
	go func() {
		log.Fatal(http.ListenAndServe(":80", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
		})))
	}()

	// HTTPS Server
	server := &http.Server{
		Addr: ":443",
		Handler: proxy,
		TLSConfig: &tls.Config{
			GetCertificate: proxy.getCertificate,
		},
	}

	// Admin-Interface starten
	go startAdminInterface(config)

	log.Println("Server startet auf :443")
	log.Fatal(server.ListenAndServeTLS("", ""))
}
