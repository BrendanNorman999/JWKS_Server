package main

//go test -coverprofile coverage.out
//go tool cover -func coverage.out

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

func init() {
	// Generate RSA key pair
	var err error

	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	publicKey = &privateKey.PublicKey

}

func main() {
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/.well-known/jwks.json", jwksHandler2)

	log.Println("Server is running on http://127.0.0.1:8080")
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", nil))
}

func authHandler(w http.ResponseWriter, r *http.Request) {

	log.Println("authHandler Start")

	switch r.Method {
	case http.MethodPost:

		expiredQueryParam := r.URL.Query().Get("expired")
		verboseQueryParam := r.URL.Query().Get("verbose")

		if verboseQueryParam == "true" {
			log.Println("Set Expiration Time.")
		}

		// Set expiration to 24 hour ahead if the query parameter expired is false.
		expirationTime := time.Now().Add(time.Hour * 24).Unix()

		if verboseQueryParam == "true" {
			log.Println("Set expiration to 1 hour ago if the query parameter expired is true.")
		}

		if expiredQueryParam == "true" {
			// Set expiration to 1 hour ago if the query parameter expired is true.
			expirationTime = time.Now().Add(-time.Hour).Unix()
		}

		if verboseQueryParam == "true" {
			log.Println("Create Claims for the JWT token.")
		}

		// Create claims for the JWT token
		claims := jwt.MapClaims{
			"sub": "JWT Assignment",
			"iat": time.Now().Unix(),
			"exp": expirationTime,
		}

		// Create the JWT token
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

		if verboseQueryParam == "true" {
			log.Println("Add the kid.")
		}

		// Add the kid.
		token.Header["kid"] = "Tommy"

		if verboseQueryParam == "true" {
			log.Println("Sign the token with the private key generated above.")
		}

		// Sign the token with the private key generated above.
		signedToken, err := token.SignedString(privateKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		if verboseQueryParam == "true" {
			log.Println("Return the signed token as the response")
		}

		// Return the signed token as the response
		json.NewEncoder(w).Encode(map[string]string{
			"token": signedToken,
		})

		log.Println("authHandler End")

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)

	}

}

func jwksHandler2(w http.ResponseWriter, r *http.Request) {

	log.Println("jwksHandler2 Start")

	switch r.Method {
	case http.MethodGet:

		// Create a new JWK set
		jwkSet := jwk.NewSet()

		// Create a new JWK from the public key
		jwkKey, err := jwk.New(publicKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Set the key ID
		jwkKey.Set(jwk.KeyIDKey, "Tommy")

		// Add the JWK to the set
		jwkSet.Add(jwkKey)

		// Marshal the JWK set to JSON
		jsonBytes, err := json.Marshal(jwkSet)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Set the response content type to application/json
		w.Header().Set("Content-Type", "application/json")

		// Write the JSON response
		w.Write(jsonBytes)

		log.Println("jwksHandler2 End")

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}

}
