package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dgrijalva/jwt-go"
)

func TestAuthHandler(t *testing.T) {
	// Create a new HTTP request
	req, err := http.NewRequest("POST", "/auth", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Call the authHandler
	authHandler(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v, want %v", status, http.StatusOK)
	}

	// Check the response body
	var response map[string]string
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the token
	token, err := jwt.Parse(response["token"], func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Errorf("failed to parse token: %v", err)
	}

	if !token.Valid {
		t.Error("token is not valid")
	}
}

func TestAuthHandlerExpired(t *testing.T) {
	// Create a new HTTP request
	req, err := http.NewRequest("POST", "/auth?expired=true&verbose=true", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Call the authHandler
	authHandler(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v, want %v", status, http.StatusOK)
	}

	// Check the response body
	var response map[string]string
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the token
	token, err := jwt.Parse(response["token"], func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Errorf("failed to parse token: %v", err)
	}

	if !token.Valid {
		t.Error("token is not valid")
	}
}

func TestAuthHandlerWrongGET(t *testing.T) {
	// Create a new HTTP request
	req, err := http.NewRequest("GET", "/auth", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Call the authHandler
	authHandler(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v, want %v", status, http.StatusOK)
	}

	// Check the response body
	var response map[string]string
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the token
	token, err := jwt.Parse(response["token"], func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Errorf("failed to parse token: %v", err)
	}

	if !token.Valid {
		t.Error("token is not valid")
	}
}

func TestAuthHandlerWrongPUT(t *testing.T) {
	// Create a new HTTP request
	req, err := http.NewRequest("PUT", "/auth", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Call the authHandler
	authHandler(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v, want %v", status, http.StatusOK)
	}

	// Check the response body
	var response map[string]string
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the token
	token, err := jwt.Parse(response["token"], func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Errorf("failed to parse token: %v", err)
	}

	if !token.Valid {
		t.Error("token is not valid")
	}
}

func TestJwksHandler2(t *testing.T) {
	// Create a new HTTP request
	req, err := http.NewRequest("GET", "/.well-known/jwks.json", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Call the jwksHandler2
	jwksHandler2(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v, want %v", status, http.StatusOK)
	}

	// Check the response body
	// var jwkSet jwk.Set
	// err = json.Unmarshal(rr.Body.Bytes(), &jwkSet)
	// if err != nil {
	// 	t.Fatal(err)
	// }

}

func TestJwksHandlerWrongPost(t *testing.T) {
	// Create a new HTTP request
	req, err := http.NewRequest("POST", "/.well-known/jwks.json", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Call the jwksHandler2
	jwksHandler2(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v, want %v", status, http.StatusOK)
	}

}

func TestJwksHandlerWrongPUT(t *testing.T) {
	// Create a new HTTP request
	req, err := http.NewRequest("PUT", "/.well-known/jwks.json", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Call the jwksHandler2
	jwksHandler2(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v, want %v", status, http.StatusOK)
	}

}
