package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
)

const createTableStatement string = "CREATE TABLE IF NOT EXISTS keys (kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL);"

//const dbFileName string = "totally_not_my_privateKeys.db"

//var sqliteDatabase *sql.DB

func TestCreateTable(t *testing.T) {

	CreateDatabase()

	CreateTable(sqliteDatabase, createTableStatement) // Create Database Tables

}

func TestCreateDatabase(t *testing.T) {

	CreateDatabase()

}

func TestGenerateKeys(t *testing.T) {
	CreateDatabase()
	GenerateKeys()
}

func TestGetKeys(t *testing.T) {
	CreateDatabase()
	GenerateKeys()

	myKid, myKey, myExp = GetKeys(true)
	// Check values.
}

func TestGetKeysExpired(t *testing.T) {
	CreateDatabase()
	GenerateKeys()

	myKid, myKey, myExp = GetKeys(false)
	// Check values.
}

func TestInsertKey(t *testing.T) {

	CreateDatabase()

	CreateTable(sqliteDatabase, createTableStatement) // Create Database Tables

	InsertKey("asldkfjaslkdjfal;skjdf", 1710714817)

}

func TestAuthHandler(t *testing.T) {

	CreateDatabase()
	GenerateKeys()

	// Create a new HTTP request
	req, err := http.NewRequest("POST", "/auth", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Call the authHandler
	AuthHandler(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v, want %v", status, http.StatusOK)
	}
}

func TestAuthHandlerGET(t *testing.T) {

	CreateDatabase()
	GenerateKeys()

	// Create a new HTTP request
	req, err := http.NewRequest("GET", "/auth", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Call the authHandler
	AuthHandler(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v, want %v", status, http.StatusOK)
	}
}

func TestAuthHandlerExpired(t *testing.T) {

	CreateDatabase()
	GenerateKeys()

	// Create a new HTTP request
	req, err := http.NewRequest("POST", "/auth?expired=true", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a response recorder
	rr := httptest.NewRecorder()

	// Call the authHandler
	AuthHandler(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v, want %v", status, http.StatusOK)
	}
}

func TestJWKSHandler(t *testing.T) {

	CreateDatabase()
	GenerateKeys()

	// Create a new HTTP request
	req, err := http.NewRequest("GET", "/.well-known/jwks.json", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a response recorder
	rr := httptest.NewRecorder()
	//handler := http.HandlerFunc(AuthHandler)

	// Call the JWKSHandler
	JWKSHandler(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v, want %v", status, http.StatusOK)
	}

}

func TestJWKSHandlerPOST(t *testing.T) {

	CreateDatabase()
	GenerateKeys()

	// Create a new HTTP request
	req, err := http.NewRequest("POST", "/.well-known/jwks.json", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a response recorder
	rr := httptest.NewRecorder()
	//handler := http.HandlerFunc(AuthHandler)

	// Call the JWKSHandler
	JWKSHandler(rr, req)

	// Check the response status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v, want %v", status, http.StatusOK)
	}

}

func TestExportRsaPrivateKeyAsPKCS1(t *testing.T) {

	goodPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("Error generating RSA keys: %v", err)
	}

	ExportRsaPrivateKeyAsPKCS1(goodPrivKey)

}

func TestParseRsaPrivateKeyFromPKCS1(t *testing.T) {

	goodPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("Error generating RSA keys: %v", err)
	}

	privkeyBytes := ExportRsaPrivateKeyAsPKCS1(goodPrivKey)

	priv, err := x509.ParsePKCS1PrivateKey(privkeyBytes)
	if err != nil {
		t.Errorf("Error generating x509 keys: %v", err)
	}

	if priv == nil {
		t.Errorf("Error generating x509 keys: %v", err)
	}

}
