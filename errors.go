package ocspstapling

import "errors"

var (
	ErrInvalidCertificate        = errors.New("invalid certificate provided")
	ErrNoOCSPServerDefined       = errors.New("no OCSP Server defined")
	ErrCouldNotCreateOCSPRequest = errors.New("could not create OCSP request")
	ErrCouldNotPostOCSPRequest   = errors.New("could not post OCSP request")
	ErrCouldNotReadOCSPResponse  = errors.New("could not read OCSP response")
	ErrCouldNotCloseBody         = errors.New("could not close response body")
	ErrCouldNotParseResponse     = errors.New("response is not a valid ocsp response")
)
