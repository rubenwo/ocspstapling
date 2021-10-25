package ocspstapling

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"golang.org/x/crypto/ocsp"
	"io"
	"net/http"
	"sync"
	"time"
)

// OCSP response may be cached 'up to 7 days'
// https://www.ssl.com/article/page-load-optimization-ocsp-stapling/

const (
	retry = 10
)

type Stapling struct {
	certificate tls.Certificate

	useOCSPStapling bool

	httpClient *http.Client

	lock sync.RWMutex
}

// ocspStaplingCanBeUsed is a helper function to check if the certificate has a valid issuer that can return an OCSP response
// i.e. self-signed certificates won't have such an issuer field
func ocspStaplingCanBeUsed(ctx context.Context, certificate tls.Certificate) bool {
	client := &http.Client{}

	retryTimer := time.NewTimer(time.Millisecond)
	defer retryTimer.Stop()

	// Retry in case of connectivity issues
	for i := 0; i < retry; i++ {
		select {
		case <-ctx.Done():
			return false
		case <-retryTimer.C:
			_, _, err := fetchOCSP(certificate, client)
			if err == nil {
				return true
			}
			if err != ErrCouldNotPostOCSPRequest {
				return false
			}
			// Increase delay between subsequent requests
			retryTimer.Reset(time.Second * time.Duration(i+1))
		}
	}

	return false
}

// NewStapling creates a new Stapling struct. The context is provided for early cancellation. The certificate is stored inside the Stapling struct.
// Certificate with the OCSP staple included can be retrieved by using the stapling.Certificate() method.
func NewStapling(ctx context.Context, certificate tls.Certificate) *Stapling {
	return &Stapling{
		certificate:     certificate,
		useOCSPStapling: ocspStaplingCanBeUsed(ctx, certificate),
		httpClient:      &http.Client{},
	}
}

// RunOCSPRenewal will run for-ever until ctx is cancelled. This function renews the OCSP staple in the internal certificate
// Every time the OCSP issuer server indicates the staple should be refreshed.
func (s *Stapling) RunOCSPRenewal(ctx context.Context) {
	if !s.useOCSPStapling {
		// RunOCSPRenewal was called without OCSP stapling supported certificate
		return
	}

	// Create a timer that fires after a second. We use this to start fetching OCSP data
	timer := time.NewTimer(time.Second)
	defer timer.Stop()

	errorCount := 0

	for {
		select {
		case <-ctx.Done():
			// Shutting down
			return
		case <-timer.C:
			// Renew certificate
			s.lock.Lock()

			resp, renewAt, err := fetchOCSP(s.certificate, s.httpClient)
			if err != nil {
				switch err {
				case ErrCouldNotPostOCSPRequest:
					s.lock.Unlock()
					// Connectivity issues might cause this error to occur, so retry in a minute.
					// If the errorCount is bigger than the retry count, we should stop trying
					if errorCount > retry {
						return
					}
					errorCount++
					timer.Reset(time.Minute)
					continue
				default:
					// In all other cases the configuration was incorrect, and we should not have been using OCSP Stapling
					s.useOCSPStapling = false
					s.lock.Unlock()
					return
				}
			}

			// Set the OCSPStaple to the raw OCSP response from the issuer
			s.certificate.OCSPStaple = resp
			// Reset the errorCount to 0 when fetching the data was successful
			errorCount = 0
			// renewAt is the time when the issuer of the certificate will renew the OCSP data.
			// At that time we need to fetch the new OCSP data.
			// Reset the timer to fire again when the OCSP cache has elapsed
			timer.Reset(time.Until(renewAt))

			s.lock.Unlock()
		}
	}
}

// Certificate returns a copy of the internal certificate as a pointer. At the moment error is always nil, but included to satisfy the GetCertificate
// function from tls.Config return value
func (s *Stapling) Certificate() (*tls.Certificate, error) {
	s.lock.RLock()
	certificate := s.certificate
	s.lock.RUnlock()
	return &certificate, nil
}

// fetchOCSP uses the certificate and httpClient to get a raw response from the Certificate issuer.
// returns the raw response, the NextUpdate time (for renewal) or an error in case something went wrong.
func fetchOCSP(certificate tls.Certificate, httpClient *http.Client) ([]byte, time.Time, error) {
	// Owner Certificate should be index 0 in chain
	x509Cert, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, time.Time{}, ErrInvalidCertificate
	}
	if len(x509Cert.OCSPServer) == 0 {
		// If there are no OCSPServers defined in the certificate, just return the TLS certificate as is.
		return nil, time.Time{}, ErrNoOCSPServerDefined
	}
	// Get the first OCSPServer. (Let's Encrypt certificates usually only have 1 OCSPServer
	ocspServer := x509Cert.OCSPServer[0]

	// The second certificate in the chain should be the issuer's certificate
	if len(certificate.Certificate) <= 1 {
		return nil, time.Time{}, ErrInvalidCertificate
	}
	x509Issuer, err := x509.ParseCertificate(certificate.Certificate[1])
	if err != nil {
		return nil, time.Time{}, ErrInvalidCertificate
	}

	// Create the OCSP request using the 'Owner certificate' and the 'Issuer certificate'
	ocspRequest, err := ocsp.CreateRequest(x509Cert, x509Issuer, nil)
	if err != nil {
		return nil, time.Time{}, ErrCouldNotCreateOCSPRequest
	}

	// POST the OCSP request to the ocspServer defined in the 'Owner certificate'
	ocspResponse, err := httpClient.Post(ocspServer, "application/ocsp-request", bytes.NewReader(ocspRequest))
	if err != nil {
		return nil, time.Time{}, ErrCouldNotPostOCSPRequest
	}

	// Read the ocsp response body
	ocspResponseData, err := io.ReadAll(ocspResponse.Body)
	if err != nil {
		return nil, time.Time{}, ErrCouldNotReadOCSPResponse
	}

	if err := ocspResponse.Body.Close(); err != nil {
		return ocspResponseData, time.Time{}, ErrCouldNotCloseBody
	}

	response, err := ocsp.ParseResponse(ocspResponseData, x509Issuer)
	if err != nil {
		return nil, time.Time{}, ErrCouldNotParseResponse
	}

	// Return the ocsp response data
	return ocspResponseData, response.NextUpdate, nil
}
