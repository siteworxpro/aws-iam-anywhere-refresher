package aws_signing_helper

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	v1 "k8s.io/api/core/v1"
	v1m "k8s.io/apimachinery/pkg/apis/meta/v1"

	"log"
	"math/big"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"golang.org/x/crypto/pkcs12"
	"golang.org/x/term"
)

type SignerParams struct {
	OverriddenDate   time.Time
	RegionName       string
	ServiceName      string
	SigningAlgorithm string
}

type CertIdentifier struct {
	Subject         string
	Issuer          string
	SerialNumber    *big.Int
	SystemStoreName string // Only relevant in the case of Windows
}

var (
	// ErrUnsupportedHash is returned by Signer.Sign() when the provided hash
	// algorithm isn't supported.
	ErrUnsupportedHash = errors.New("unsupported hash algorithm")

	RolesanywhereSigningName = "rolesanywhere"
)

type Signer interface {
	Public() crypto.PublicKey
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
	Certificate() (certificate *x509.Certificate, err error)
	CertificateChain() (certificateChain []*x509.Certificate, err error)
	Close()
}

type CertificateData struct {
	// Type for the key contained in the certificate.
	// Passed back to the `sign-string` command
	KeyType string `json:"keyType"`
	// Certificate, as base64-encoded DER; used in the `x-amz-x509`
	// header in the API request.
	CertificateData string `json:"certificateData"`
	// Serial number of the certificate. Used in the credential
	// field of the Authorization header
	SerialNumber string `json:"serialNumber"`
	// Supported signing algorithms based on the KeyType
	Algorithms []string `json:"supportedAlgorithms"`
}

type CredentialProcessOutput struct {
	// This field should be hard-coded to 1 for now.
	Version int `json:"Version"`
	// AWS Access Key ID
	AccessKeyId string `json:"AccessKeyId"`
	// AWS Secret Access Key
	SecretAccessKey string `json:"SecretAccessKey"`
	// AWS Session Token for temporary credentials
	SessionToken string `json:"SessionToken"`
	// ISO8601 timestamp for when the credentials expire
	Expiration string `json:"Expiration"`
}

type CertificateContainer struct {
	// Index (can be useful in sorting)
	Index int
	// Certificate data
	Cert *x509.Certificate
	// Certificate URI (only populated in the case that the certificate is a PKCS#11 object)
	Uri string
}

// Define constants used in signing
const (
	aws4X509RsaSha256   = "AWS4-X509-RSA-SHA256"
	aws4X509EcdsaSha256 = "AWS4-X509-ECDSA-SHA256"
	timeFormat          = "20060102T150405Z"
	shortTimeFormat     = "20060102"
	xAmzDate            = "X-Amz-Date"
	xAmzX509            = "X-Amz-X509"
	xAmzX509Chain       = "X-Amz-X509-Chain"
	authorization       = "Authorization"
	host                = "Host"
)

// Headers that aren't included in calculating the signature
var ignoredHeaderKeys = map[string]bool{
	"Authorization":   true,
	"User-Agent":      true,
	"X-Amzn-Trace-Id": true,
}

var Debug = false

func GetPassword(ttyReadFile *os.File, ttyWriteFile *os.File, prompt string, parseErrMsg string) (string, error) {
	_, _ = fmt.Fprintln(ttyWriteFile, prompt)
	passwordBytes, err := term.ReadPassword(int(ttyReadFile.Fd()))
	if err != nil {
		return "", errors.New(parseErrMsg)
	}

	password := string(passwordBytes[:])
	strings.Replace(password, "\r", "", -1) // Remove CR
	return password, nil
}

type PasswordPromptProps struct {
	InitialPassword                    string
	NoPassword                         bool
	CheckPassword                      func(string) (interface{}, error)
	IncorrectPasswordMsg               string
	Prompt                             string
	Reprompt                           string
	ParseErrMsg                        string
	CheckPasswordAuthorizationErrorMsg string
}

func PasswordPrompt(passwordPromptInput PasswordPromptProps) (string, interface{}, error) {
	var (
		err                                error
		ttyReadPath                        string
		ttyWritePath                       string
		ttyReadFile                        *os.File
		ttyWriteFile                       *os.File
		parseErrMsg                        string
		prompt                             string
		reprompt                           string
		password                           string
		incorrectPasswordMsg               string
		checkPasswordAuthorizationErrorMsg string
		checkPassword                      func(string) (interface{}, error)
		checkPasswordResult                interface{}
		noPassword                         bool
	)

	password = passwordPromptInput.InitialPassword
	noPassword = passwordPromptInput.NoPassword
	incorrectPasswordMsg = passwordPromptInput.IncorrectPasswordMsg
	prompt = passwordPromptInput.Prompt
	reprompt = passwordPromptInput.Reprompt
	parseErrMsg = passwordPromptInput.ParseErrMsg
	checkPassword = passwordPromptInput.CheckPassword
	checkPasswordAuthorizationErrorMsg = passwordPromptInput.CheckPasswordAuthorizationErrorMsg

	ttyReadPath = "/dev/tty"
	ttyWritePath = ttyReadPath
	if runtime.GOOS == "windows" {
		ttyReadPath = "CONIN$"
		ttyWritePath = "CONOUT$"
	}

	// If no password is required
	if noPassword {
		checkPasswordResult, err = checkPassword("")
		if err != nil {
			return "", nil, err
		}
		return "", checkPasswordResult, nil
	}

	// If the password was provided explicitly, beforehand
	if password != "" {
		checkPasswordResult, err = checkPassword(password)
		if err != nil {
			return "", nil, errors.New(incorrectPasswordMsg)
		}
		return password, checkPasswordResult, nil
	}

	ttyReadFile, err = os.OpenFile(ttyReadPath, os.O_RDWR, 0)
	if err != nil {
		return "", nil, errors.New(parseErrMsg)
	}
	defer func(ttyReadFile *os.File) {
		_ = ttyReadFile.Close()
	}(ttyReadFile)

	ttyWriteFile, err = os.OpenFile(ttyWritePath, os.O_WRONLY, 0)
	if err != nil {
		return "", nil, errors.New(parseErrMsg)
	}
	defer func(ttyWriteFile *os.File) {
		_ = ttyWriteFile.Close()
	}(ttyWriteFile)

	// The key has a password, so prompt for it
	password, err = GetPassword(ttyReadFile, ttyWriteFile, prompt, parseErrMsg)
	if err != nil {
		return "", nil, err
	}
	checkPasswordResult, err = checkPassword(password)
	for {
		// If we've found the right password, return both it and the result of `checkPassword`
		if err == nil {
			return password, checkPasswordResult, nil
		}
		// Otherwise, if the password was incorrect, prompt for it again
		if strings.Contains(err.Error(), checkPasswordAuthorizationErrorMsg) {
			password, err = GetPassword(ttyReadFile, ttyWriteFile, reprompt, parseErrMsg)
			if err != nil {
				return "", nil, err
			}
			checkPasswordResult, err = checkPassword(password)
			continue
		}
		return "", nil, err
	}
}

func DefaultCertContainerToString(certContainer CertificateContainer) string {
	var certStr string

	cert := certContainer.Cert

	fingerprint := sha1.Sum(cert.Raw) // nosemgrep
	fingerprintHex := hex.EncodeToString(fingerprint[:])
	certStr = fmt.Sprintf("%s \"%s\"\n", fingerprintHex, cert.Subject.String())

	// Only for PKCS#11
	if certContainer.Uri != "" {
		certStr += fmt.Sprintf("\tURI: %s\n", certContainer.Uri)
	}

	return certStr
}

type CertificateContainerList []CertificateContainer

func (certificateContainerList CertificateContainerList) Less(i, j int) bool {
	return certificateContainerList[i].Cert.NotAfter.Before(certificateContainerList[j].Cert.NotAfter)
}

func (certificateContainerList CertificateContainerList) Swap(i, j int) {
	certificateContainerList[i], certificateContainerList[j] = certificateContainerList[j], certificateContainerList[i]
}

func (certificateContainerList CertificateContainerList) Len() int {
	return len(certificateContainerList)
}

// Find whether the current certificate matches the CertIdentifier
func certMatches(certIdentifier CertIdentifier, cert x509.Certificate) bool {
	if certIdentifier.Subject != "" && certIdentifier.Subject != cert.Subject.String() {
		return false
	}
	if certIdentifier.Issuer != "" && certIdentifier.Issuer != cert.Issuer.String() {
		return false
	}
	if certIdentifier.SerialNumber != nil && certIdentifier.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		return false
	}

	return true
}

// Because of *course* we have to do this for ourselves.
//
// Create the DER-encoded SEQUENCE containing R and S:
//
//	Ecdsa-Sig-Value ::= SEQUENCE {
//	  r                   INTEGER,
//	  s                   INTEGER
//	}
//
// This is defined in RFC3279 §2.2.3 as well as SEC.1.
// I can't find anything which mandates DER, but I've seen
// OpenSSL refusing to verify it with indeterminate length.
func encodeEcdsaSigValue(signature []byte) (out []byte, err error) {
	sigLen := len(signature) / 2

	return asn1.Marshal(struct {
		R *big.Int
		S *big.Int
	}{
		big.NewInt(0).SetBytes(signature[:sigLen]),
		big.NewInt(0).SetBytes(signature[sigLen:])})
}

// GetSigner gets the Signer based on the flags passed in by the user (from which the CredentialsOpts structure is derived)
func GetSigner(opts *CredentialsOpts) (signer Signer, signatureAlgorithm string, err error) {
	var (
		certificate      *x509.Certificate
		certificateChain []*x509.Certificate
	)

	privateKeyId := opts.PrivateKeyId
	if privateKeyId == "" {
		if opts.CertificateId == "" {
			return GetCertStoreSigner(opts.CertIdentifier, opts.UseLatestExpiringCertificate)
		}
		privateKeyId = opts.CertificateId
	}

	if opts.CertificateId != "" && !strings.HasPrefix(opts.CertificateId, "pkcs11:") {
		_, cert, err := ReadCertificateData(opts.CertificateId)
		if err == nil {
			certificate = cert
		} else if opts.PrivateKeyId == "" {

			if opts.CertificateBundleId != "" {
				return nil, "", errors.New("can't specify certificate chain when" +
					" using PKCS#12 files; certificate bundle should be provided" +
					" within the PKCS#12 file")
			}
			// Not a PEM certificate? Try PKCS#12
			_, _, err = ReadPKCS12Data(opts.CertificateId)
			if err != nil {
				return nil, "", err
			}
			return GetFileSystemSigner(opts.PrivateKeyId, opts.CertificateId, opts.CertificateBundleId, true, opts.Pkcs8Password)
		} else {
			return nil, "", err
		}
	}

	if opts.CertificateBundleId != "" {
		certificateChain, err = GetCertChain(opts.CertificateBundleId)
		if err != nil {
			return nil, "", err
		}
	}

	if strings.HasPrefix(privateKeyId, "pkcs11:") {
		if certificate != nil {
			opts.CertificateId = ""
		}
		return GetPKCS11Signer(opts.LibPkcs11, certificate, certificateChain, opts.PrivateKeyId, opts.CertificateId, opts.ReusePin)
	} else if strings.HasPrefix(privateKeyId, "handle:") {
		return GetTPMv2Signer(
			GetTPMv2SignerOpts{
				certificate,
				certificateChain,
				nil,
				opts.TpmKeyPassword,
				opts.NoTpmKeyPassword,
				opts.PrivateKeyId,
			},
		)
	} else {
		tpmKey, err := parseDERFromPEM(privateKeyId, "TSS2 PRIVATE KEY")
		if err == nil {
			return GetTPMv2Signer(
				GetTPMv2SignerOpts{
					certificate,
					certificateChain,
					tpmKey,
					opts.TpmKeyPassword,
					opts.NoTpmKeyPassword,
					"",
				},
			)
		}

		if !isPKCS8EncryptedBlockType(privateKeyId) {
			_, err = ReadPrivateKeyData(privateKeyId, opts.Pkcs8Password)
			if err != nil {
				return nil, "", err
			}
		}

		if certificate == nil {
			return nil, "", errors.New("undefined certificate value")
		}
		return GetFileSystemSigner(privateKeyId, opts.CertificateId, opts.CertificateBundleId, false, opts.Pkcs8Password)
	}
}

func (signerParams *SignerParams) GetFormattedSigningDateTime() string {
	return signerParams.OverriddenDate.UTC().Format(timeFormat)
}

func (signerParams *SignerParams) GetFormattedShortSigningDateTime() string {
	return signerParams.OverriddenDate.UTC().Format(shortTimeFormat)
}

func (signerParams *SignerParams) GetScope() string {
	var scopeStringBuilder strings.Builder
	scopeStringBuilder.WriteString(signerParams.GetFormattedShortSigningDateTime())
	scopeStringBuilder.WriteString("/")
	scopeStringBuilder.WriteString(signerParams.RegionName)
	scopeStringBuilder.WriteString("/")
	scopeStringBuilder.WriteString(signerParams.ServiceName)
	scopeStringBuilder.WriteString("/")
	scopeStringBuilder.WriteString("aws4_request")
	return scopeStringBuilder.String()
}

// Convert certificate to string, so that it can be present in the HTTP request header
func certificateToString(certificate *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(certificate.Raw)
}

// Convert certificate chain to string, so that it can be pressent in the HTTP request header
func certificateChainToString(certificateChain []*x509.Certificate) string {
	var x509ChainString strings.Builder
	for i, certificate := range certificateChain {
		x509ChainString.WriteString(certificateToString(certificate))
		if i != len(certificateChain)-1 {
			x509ChainString.WriteString(",")
		}
	}
	return x509ChainString.String()
}

func CreateRequestSignFinalizeFunction(signer crypto.Signer, signingRegion string, signingAlgorithm string, certificate *x509.Certificate, certificateChain []*x509.Certificate) func(context.Context, middleware.FinalizeInput, middleware.FinalizeHandler) (middleware.FinalizeOutput, middleware.Metadata, error) {
	return func(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (out middleware.FinalizeOutput, metadata middleware.Metadata, err error) {
		req, ok := in.Request.(*smithyhttp.Request)
		if !ok {
			return out, metadata, errors.New(fmt.Sprintf("unexpected request middleware type %T", in.Request))
		}

		payloadHash := v4.GetPayloadHash(ctx)
		signRequest(signer, signingRegion, signingAlgorithm, certificate, certificateChain, req.Request, payloadHash)

		return next.HandleFinalize(ctx, in)
	}
}

func signRequest(signer crypto.Signer, signingRegion string, signingAlgorithm string, certificate *x509.Certificate, certificateChain []*x509.Certificate, req *http.Request, payloadHash string) {
	signerParams := SignerParams{time.Now(), signingRegion, RolesanywhereSigningName, signingAlgorithm}

	// Set headers that are necessary for signing
	req.Header.Set(host, req.URL.Host)
	req.Header.Set(xAmzDate, signerParams.GetFormattedSigningDateTime())
	req.Header.Set(xAmzX509, certificateToString(certificate))
	if certificateChain != nil {
		req.Header.Set(xAmzX509Chain, certificateChainToString(certificateChain))
	}

	canonicalRequest, signedHeadersString := createCanonicalRequest(req, payloadHash)

	stringToSign := CreateStringToSign(canonicalRequest, signerParams)
	signatureBytes, err := signer.Sign(rand.Reader, []byte(stringToSign), crypto.SHA256)
	if err != nil {
		log.Println("could not sign request", err)
		os.Exit(1)
	}
	signature := hex.EncodeToString(signatureBytes)

	req.Header.Set(authorization, BuildAuthorizationHeader(req, signedHeadersString, signature, certificate, signerParams))
}

// Create the canonical query string.
func createCanonicalQueryString(r *http.Request) string {
	rawQuery := strings.Replace(r.URL.Query().Encode(), "+", "%20", -1)
	return rawQuery
}

// Create the canonical header string.
func createCanonicalHeaderString(r *http.Request) (string, string) {
	var headers []string
	signedHeaderVals := make(http.Header)
	for k, v := range r.Header {
		canonicalKey := http.CanonicalHeaderKey(k)
		if ignoredHeaderKeys[canonicalKey] {
			continue
		}

		lowerCaseKey := strings.ToLower(k)
		if _, ok := signedHeaderVals[lowerCaseKey]; ok {
			// include additional values
			signedHeaderVals[lowerCaseKey] = append(signedHeaderVals[lowerCaseKey], v...)
			continue
		}

		headers = append(headers, lowerCaseKey)
		signedHeaderVals[lowerCaseKey] = v
	}
	sort.Strings(headers)

	headerValues := make([]string, len(headers))
	for i, k := range headers {
		headerValues[i] = k + ":" + strings.Join(signedHeaderVals[k], ",")
	}
	stripExcessSpaces(headerValues)
	return strings.Join(headerValues, "\n"), strings.Join(headers, ";")
}

const doubleSpace = "  "

// stripExcessSpaces will rewrite the passed in slice's string values to not
// contain muliple side-by-side spaces.
func stripExcessSpaces(vals []string) {
	var j, k, l, m, spaces int
	for i, str := range vals {
		// Trim trailing spaces
		for j = len(str) - 1; j >= 0 && str[j] == ' '; j-- {
		}

		// Trim leading spaces
		for k = 0; k < j && str[k] == ' '; k++ {
		}
		str = str[k : j+1]

		// Strip multiple spaces.
		j = strings.Index(str, doubleSpace)
		if j < 0 {
			vals[i] = str
			continue
		}

		buf := []byte(str)
		for k, m, l = j, j, len(buf); k < l; k++ {
			if buf[k] == ' ' {
				if spaces == 0 {
					// First space.
					buf[m] = buf[k]
					m++
				}
				spaces++
			} else {
				// End of multiple spaces.
				spaces = 0
				buf[m] = buf[k]
				m++
			}
		}

		vals[i] = string(buf[:m])
	}
}

// Create the canonical request.
func createCanonicalRequest(r *http.Request, contentSha256 string) (string, string) {
	var canonicalRequestStrBuilder strings.Builder
	canonicalHeaderString, signedHeadersString := createCanonicalHeaderString(r)
	canonicalRequestStrBuilder.WriteString("POST")
	canonicalRequestStrBuilder.WriteString("\n")
	canonicalRequestStrBuilder.WriteString("/sessions")
	canonicalRequestStrBuilder.WriteString("\n")
	canonicalRequestStrBuilder.WriteString(createCanonicalQueryString(r))
	canonicalRequestStrBuilder.WriteString("\n")
	canonicalRequestStrBuilder.WriteString(canonicalHeaderString)
	canonicalRequestStrBuilder.WriteString("\n\n")
	canonicalRequestStrBuilder.WriteString(signedHeadersString)
	canonicalRequestStrBuilder.WriteString("\n")
	canonicalRequestStrBuilder.WriteString(contentSha256)
	canonicalRequestString := canonicalRequestStrBuilder.String()
	canonicalRequestStringHashBytes := sha256.Sum256([]byte(canonicalRequestString))
	return hex.EncodeToString(canonicalRequestStringHashBytes[:]), signedHeadersString
}

func CreateStringToSign(canonicalRequest string, signerParams SignerParams) string {
	var stringToSignStrBuilder strings.Builder
	stringToSignStrBuilder.WriteString(signerParams.SigningAlgorithm)
	stringToSignStrBuilder.WriteString("\n")
	stringToSignStrBuilder.WriteString(signerParams.GetFormattedSigningDateTime())
	stringToSignStrBuilder.WriteString("\n")
	stringToSignStrBuilder.WriteString(signerParams.GetScope())
	stringToSignStrBuilder.WriteString("\n")
	stringToSignStrBuilder.WriteString(canonicalRequest)
	stringToSign := stringToSignStrBuilder.String()
	return stringToSign
}

func BuildAuthorizationHeader(_ *http.Request, signedHeadersString string, signature string, certificate *x509.Certificate, signerParams SignerParams) string {
	signingCredentials := certificate.SerialNumber.String() + "/" + signerParams.GetScope()
	credential := "Credential=" + signingCredentials
	signerHeaders := "SignedHeaders=" + signedHeadersString
	signatureHeader := "Signature=" + signature

	var authHeaderStringBuilder strings.Builder
	authHeaderStringBuilder.WriteString(signerParams.SigningAlgorithm)
	authHeaderStringBuilder.WriteString(" ")
	authHeaderStringBuilder.WriteString(credential)
	authHeaderStringBuilder.WriteString(", ")
	authHeaderStringBuilder.WriteString(signerHeaders)
	authHeaderStringBuilder.WriteString(", ")
	authHeaderStringBuilder.WriteString(signatureHeader)
	authHeaderString := authHeaderStringBuilder.String()
	return authHeaderString
}

func encodeDer(der []byte) (string, error) {
	var buf bytes.Buffer
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	_, _ = encoder.Write(der)
	_ = encoder.Close()
	return buf.String(), nil
}

func parseDERFromPEM(pemDataId string, blockType string) (*pem.Block, error) {
	b := []byte(pemDataId)

	var block *pem.Block
	for len(b) > 0 {
		block, b = pem.Decode(b)
		if block == nil {
			return nil, errors.New("unable to parse PEM data")
		}
		if block.Type == blockType {
			return block, nil
		}
	}
	return nil, errors.New("requested block type could not be found")
}

func ReadCertificateBundleData(certificateBundleId string) ([]*x509.Certificate, error) {

	var derBytes []byte
	var block *pem.Block
	block, _ = pem.Decode([]byte(certificateBundleId))

	if block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid certificate chain")
	}

	blockBytes := block.Bytes
	derBytes = append(derBytes, blockBytes...)

	return x509.ParseCertificates(derBytes)
}

func readECPrivateKey(privateKeyId string) (*ecdsa.PrivateKey, error) {
	block, err := parseDERFromPEM(privateKeyId, "EC PRIVATE KEY")
	if err != nil {
		return nil, errors.New("could not parse PEM data")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("could not parse private key")
	}

	return privateKey, nil
}

func readRSAPrivateKey(privateKeyId string) (*rsa.PrivateKey, error) {
	block, err := parseDERFromPEM(privateKeyId, "RSA PRIVATE KEY")
	if err != nil {
		return nil, errors.New("could not parse PEM data")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("could not parse private key")
	}

	return privateKey, nil
}

func ReadPKCS12Data(certificateId string) (certChain []*x509.Certificate, privateKey crypto.PrivateKey, err error) {
	var (
		bts                 []byte
		pemBlocks           []*pem.Block
		parsedCerts         []*x509.Certificate
		certMap             map[string]*x509.Certificate
		endEntityFoundIndex int
	)

	bts, err = os.ReadFile(certificateId)
	if err != nil {
		return nil, nil, err
	}

	pemBlocks, err = pkcs12.ToPEM(bts, "")
	if err != nil {
		return nil, "", err
	}

	for _, block := range pemBlocks {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			parsedCerts = append(parsedCerts, cert)
			continue
		}
		privateKeyTmp, err := ReadPrivateKeyDataFromPEMBlock(block)
		if err == nil {
			privateKey = privateKeyTmp
			continue
		}
	}

	certMap = make(map[string]*x509.Certificate)
	for _, cert := range parsedCerts {
		// pkix.Name.String() roughly follows the RFC 2253 Distinguished Names
		// syntax, so we assume that it's canonical.
		issuer := cert.Issuer.String()
		certMap[issuer] = cert
	}

	endEntityFoundIndex = -1
	for i, cert := range parsedCerts {
		subject := cert.Subject.String()
		if _, ok := certMap[subject]; !ok {
			certChain = append(certChain, cert)
			endEntityFoundIndex = i
			break
		}
	}
	for i, cert := range parsedCerts {
		if i != endEntityFoundIndex {
			certChain = append(certChain, cert)
		}
	}

	return certChain, privateKey, nil
}

func ReadPrivateKeyData(privateKeyId string, pkcs8Password ...string) (crypto.PrivateKey, error) {
	if len(pkcs8Password) > 0 && pkcs8Password[0] != "" {
		if key, err := readPKCS8EncryptedPrivateKey(privateKeyId, []byte(pkcs8Password[0])); err == nil {
			return key, nil
		}
		return nil, errors.New("unable to parse private key")
	}

	if key, err := readPKCS8PrivateKey(privateKeyId); err == nil {
		return key, nil
	}

	// Try EC and RSA keys as a fallback
	if key, err := readECPrivateKey(privateKeyId); err == nil {
		return key, nil
	}

	if key, err := readRSAPrivateKey(privateKeyId); err == nil {
		return key, nil
	}

	return nil, errors.New("unable to parse private key")
}

func ReadPrivateKeyDataFromPEMBlock(block *pem.Block) (key crypto.PrivateKey, err error) {
	key, err = x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}

	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}

	return nil, errors.New("unable to parse private key")
}

// ReadCertificateData loads the certificate referenced by `certificateId` and extracts
// details required by the SDK to construct the StringToSign.
func ReadCertificateData(certificateId string) (CertificateData, *x509.Certificate, error) {
	block, err := parseDERFromPEM(certificateId, "CERTIFICATE")
	if err != nil {
		return CertificateData{}, nil, errors.New("could not parse PEM data")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return CertificateData{}, nil, errors.New("could not parse certificate")
	}

	//extract serial number
	serialNumber := cert.SerialNumber.String()

	//encode certificate
	encodedDer, _ := encodeDer(block.Bytes)

	//extract key type
	var keyType string
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		keyType = "RSA"
	case x509.ECDSA:
		keyType = "EC"
	default:
		keyType = ""
	}

	supportedAlgorithms := []string{
		fmt.Sprintf("%sSHA256", keyType),
		fmt.Sprintf("%sSHA384", keyType),
		fmt.Sprintf("%sSHA512", keyType),
	}

	//return struct
	return CertificateData{keyType, encodedDer, serialNumber, supportedAlgorithms}, cert, nil
}

// GetCertChain reads a certificate bundle and returns a chain of all the certificates it contains
func GetCertChain(certificateBundleId string) ([]*x509.Certificate, error) {
	certificateChainPointers, err := ReadCertificateBundleData(certificateBundleId)
	var chain []*x509.Certificate
	if err != nil {
		return nil, err
	}
	for _, certificate := range certificateChainPointers {
		chain = append(chain, certificate)
	}
	return chain, nil
}

func (credentials CredentialProcessOutput) ToSecret(secretName string) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: v1m.ObjectMeta{
			Name: secretName,
			Labels: map[string]string{
				"managed-by": "aws-iam-anywhere-refresher",
			},
		},
		StringData: map[string]string{
			"AWS_ACCESS_KEY_ID":     credentials.AccessKeyId,
			"AWS_SECRET_ACCESS_KEY": credentials.SecretAccessKey,
			"AWS_SESSION_TOKEN":     credentials.SessionToken,
		},
	}

}
