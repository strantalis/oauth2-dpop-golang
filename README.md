# OAuth2 DPoP Golang Example

DPoP Spec: https://datatracker.ietf.org/doc/html/draft-fett-oauth-dpop-03

This sample code uses the client credentials grant with private/secret key JWT authentication to obtain an access token. It also demonstrates how the DPoP proof flow works with an IDP like Okta.

## Generate DPoP Key (Testing Only)

`openssl genrsa -out dpopkey.pem 2048`

`go run main.go --file privatekey.pem --client-id <client id> --token-endpoint <token-endpoint> --audience <token-endpoint> --pem true --dpop true --dpop-key dpopkey.pem --kid test --scopes okta.users.read`
