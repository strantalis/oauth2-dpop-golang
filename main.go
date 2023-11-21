package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"golang.org/x/oauth2"
)

func main() {
	var (
		dpopKey   *rsa.PrivateKey
		dpopToken string
		err       error
		key       jwk.Key
	)

	file := flag.String("file", "", "file to read private key from")
	pem := flag.Bool("pem", false, "whether the private key is PEM encoded")
	kid := flag.String("kid", "", "name of key id")
	clientID := flag.String("client-id", "", "client id")
	clientSecret := flag.String("client-secret", "", "client secret")
	audience := flag.String("audience", "", "audience")
	scopes := flag.String("scopes", "", "scopes to use for the assertion")
	tokenEndpoint := flag.String("token-endpoint", "", "oauth2 token endpoint")
	dpopKeyFile := flag.String("dpop-key", "dpopkey.pem", "dpop private key")
	dpop := flag.Bool("dpop", false, "enable dpop flow")
	flag.Parse()

	// Hardcoded
	logger := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	slog.SetDefault(slog.New(logger))

	slog.Debug("flags", slog.String("file", *file), slog.Bool("pem", *pem), slog.String("kid", *kid), slog.String("client-id", *clientID), slog.String("audience", *audience), slog.String("token-endpoint", *tokenEndpoint), slog.String("dpop-key", *dpopKeyFile), slog.Bool("dpop", *dpop))

	if *dpop {
		dpopKey, err = ReadPrivateKey(*dpopKeyFile)
		if err != nil {
			slog.Error("failed to read dpop private key", slog.Any("error", err))
			return
		}
	}

	// Can't support both file and client-secret signing
	if *file == "" && *clientSecret == "" {
		slog.Error("must provide either file or client-secret")
		return
	}
	// Read private key from file
	if *file != "" {
		var exists bool

		jwk.FromRaw([]byte(*clientSecret))
		keySet, err := jwk.ReadFile(*file, jwk.WithPEM(*pem))
		if err != nil {
			slog.Error("failed to create JWK from private key", slog.Any("error", err))
			return
		}
		key, exists = keySet.Key(0)
		if !exists {
			slog.Error("failed to get key from keyset")
			return
		}
		key.Set("alg", jwa.RS256)
	}

	// Read client secret from flag
	if *clientSecret != "" {
		key, err = jwk.FromRaw([]byte(*clientSecret))
		if err != nil {
			slog.Error("failed to create JWK from secret", slog.Any("error", err))
			return
		}
		key.Set("alg", jwa.HS256)
	}

	// Set key id for later use
	key.Set("kid", *kid)

	// Build client assertion
	signedToken, err := BuildClientAssertion(*clientID, *audience, key)
	if err != nil {
		slog.Error("failed to sign token", slog.Any("error", err))
		return
	}
	slog.Debug("signed token", slog.Any("token", string(signedToken)))

	// Build dpop token
	if *dpop {
		dpopToken, err = DPoP(dpopKey, http.MethodPost, *tokenEndpoint, "")
		if err != nil {
			slog.Error("failed to create dpop token", slog.Any("error", err))
			return
		}
	}
	var s []string
	if *scopes != "" {
		s = strings.Split(*scopes, ",")
	}

	// Get Access Token
	tokens, dpopNonce, err := Token(*tokenEndpoint, signedToken, s, dpopToken)
	if err != nil {
		slog.Error("failed to get token", slog.Any("error", err))
		return
	}

	// If we get a nonce back we need to send another request with the nonce
	if dpopNonce != "" {
		dpopToken, err = DPoP(dpopKey, http.MethodPost, *tokenEndpoint, dpopNonce)
		if err != nil {
			slog.Error("failed to create dpop token on nonce request", slog.Any("error", err))
			return
		}
		signedToken, err = BuildClientAssertion(*clientID, *audience, key)
		if err != nil {
			slog.Error("failed to sign token", slog.Any("error", err))
			return
		}
		tokens, _, err = Token(*tokenEndpoint, signedToken, s, dpopToken)
		if err != nil {
			slog.Error("failed to get token on nonce request", slog.Any("error", err))
			return
		}
	}
	slog.Info("token", slog.Any("token", tokens.AccessToken), slog.Any("expires", tokens.Expiry))

}

func BuildClientAssertion(clientID, audience string, key jwk.Key) ([]byte, error) {
	tok, err := jwt.NewBuilder().
		Issuer(clientID).
		Subject(clientID).
		Audience([]string{audience}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(5 * time.Minute)).
		JwtID(uuid.NewString()).
		Build()
	if err != nil {
		slog.Error("failed to build assertion payload", slog.Any("error", err))
		return nil, err
	}
	headers := jws.NewHeaders()

	if key.KeyID() != "" {
		headers.Set("kid", key.KeyID())
	}

	return jwt.Sign(tok, jwt.WithKey(key.Algorithm(), key, jws.WithProtectedHeaders(headers)))
}

func Token(tokenEndpoint string, signedToken []byte, scopes []string, dpopToken string) (*oauth2.Token, string, error) {
	client := http.Client{}
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	if len(scopes) > 0 {
		fmt.Println(len(scopes))
		data.Set("scope", strings.Join(scopes, " "))
	}
	data.Set("assertion", string(signedToken))
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("client_assertion", string(signedToken))

	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, "", err
	}

	req.Form = data
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if dpopToken != "" {
		slog.Debug("adding dpop header", slog.String("dpop", dpopToken))
		req.Header.Add("DPoP", dpopToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}

	slog.Debug("token response", slog.Any("body", string(body)), slog.Any("status", resp.StatusCode))

	/*
		Okta supports dpop-nonce so it requires 2 requests
		Not sure if this is in the spec but okta returns this in the body on the first request
		{"error":"use_dpop_nonce","error_description":"Authorization server requires nonce in DPoP proof."}
	*/
	if nonce := resp.Header.Get("dpop-nonce"); nonce != "" && resp.StatusCode == http.StatusBadRequest {
		return nil, nonce, nil
	}

	var tokens *oauth2.Token
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, "", err
	}
	return tokens, "", nil
}

func ReadPrivateKey(file string) (*rsa.PrivateKey, error) {
	keyFile, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer keyFile.Close()

	privkey, err := io.ReadAll(keyFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privkey)
	if block == nil {
		return nil, errors.New("failed to decode private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	return key.(*rsa.PrivateKey), err
}

func DPoP(privateKey *rsa.PrivateKey, method string, endpoint string, nonce string) (string, error) {
	slog.Debug("Building DPoP Proof")
	publicKey, err := jwk.FromRaw(privateKey.PublicKey)
	if err != nil {
		panic(err)
	}
	publicKey.Set("use", "sig")
	publicKey.Set("alg", jwa.RS256)

	privateJWK, err := jwk.FromRaw(privateKey)
	if err != nil {
		panic(err)
	}

	tokenBuilder := jwt.NewBuilder().
		Claim("jti", uuid.NewString()).
		Claim("htm", method).
		Claim("htu", endpoint).
		Claim("iat", time.Now().Unix()).
		Claim("exp", time.Now().Add(5*time.Minute).Unix())

	if nonce != "" {
		tokenBuilder.Claim("nonce", nonce)
	}

	token, err := tokenBuilder.Build()
	if err != nil {
		return "", err
	}

	//Protected headers
	headers := jws.NewHeaders()
	headers.Set("jwk", publicKey)
	headers.Set("typ", "dpop+jwt")

	proof, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, privateJWK, jws.WithProtectedHeaders(headers)))
	if err != nil {
		panic(err)
	}

	return string(proof), nil

}
