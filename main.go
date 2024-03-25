package main

// go mod init JWKS-Assignment2v1
// go get github.com/golang-jwt/jwt/v5
// CREATE TABLE IF NOT EXISTS keys (kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL);
// go get github.com/mattn/go-sqlite3
// Binary was compiled with 'CGO_ENABLED=0', go-sqlite3 requires cgo to work. This is a stub
//		https://github.com/go-gorm/gorm/issues/6468
//		go env CGO_ENABLED
//		go env -w CGO_ENABLED=1
// cgo: C compiler "gcc" not found: exec: "gcc": executable file not found in %PATH% (exit status 1)
//		https://code.visualstudio.com/docs/cpp/config-mingw
//		https://www.msys2.org/
//		I think this is what fixed it.  https://code.visualstudio.com/docs/cpp/config-mingw and adding C:\msys64\ucrt64\bin to the path.

// Use a struct to get rows from DB: https://stackoverflow.com/questions/66473517/how-do-i-query-a-sqlite-db-in-go

// string encoding like PKCS1 PEM
// https://stackoverflow.com/questions/13555085/save-and-load-crypto-rsa-privatekey-to-and-from-the-disk

// SQLite Sample
// https://www.codeproject.com/Articles/5261771/Golang-SQLite-Simple-Example

// https://jwt.io/ Test JWT.

// ToDo:
// 	May want to change errors funcation calls in PEMStr functions to the same used elsewhere.
//	When to close the database.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
)

func main() {

	// Call to function that creates the databae and then calls function to create the tables.
	CreateDatabase()

	// Call to function that generates both a valid and an expired key.  This function inserts the keys into the database created above.
	GenerateKeys()

	http.HandleFunc("/.well-known/jwks.json", JWKSHandler)
	http.HandleFunc("/auth", AuthHandler)

	// Start the listener
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", nil))
}

// File name for the database.  It is created in the same directory as the program.
const dbFileName string = "totally_not_my_privateKeys.db"

var (
	goodPrivKey    *rsa.PrivateKey
	expiredPrivKey *rsa.PrivateKey
	myKid          int
	myKey          *rsa.PrivateKey
	myExp          int64
	sqliteDatabase *sql.DB
)

// Function to create the SQLite database.
func CreateDatabase() {

	// Create table SQL DDL.
	const createTableStatement string = "CREATE TABLE IF NOT EXISTS keys (kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL);"

	// Delete the database file if it exists already.
	os.Remove(dbFileName)

	log.Println("Creating sqlite database")

	// Create the file.
	file, err := os.Create(dbFileName)
	if err != nil {
		log.Fatal(err.Error())
	}
	file.Close()

	log.Println("sqlite database created")

	sqliteDatabase, _ = sql.Open("sqlite3", dbFileName) // Open the created SQLite File

	//defer sqliteDatabase.Close()                      // Defer Closing the database
	CreateTable(sqliteDatabase, createTableStatement) // Create Database Tables

}

func GenerateKeys() {

	var err error
	var goodPrivKeyPEM string
	var expiredPrivKeyPEM string

	goodPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating RSA keys: %v", err)
	}

	// Serialize rsa.PriveKey to PEM String so we can store it in the database.
	goodPrivKeyPEM = string(ExportRsaPrivateKeyAsPKCS1(goodPrivKey))

	myTime := time.Now().Add(1 * time.Hour).Unix()

	// Insert non-expired key record in the database.
	InsertKey(goodPrivKeyPEM, myTime)

	// Generate an expired key pair for demonstration purposes
	expiredPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating expired RSA keys: %v", err)
	}

	// Serialize rsa.PriveKey to PEM String so we can store it in the database.
	expiredPrivKeyPEM = string(ExportRsaPrivateKeyAsPKCS1(expiredPrivKey))

	// Generate expired key time one hour in the past.
	myTime = time.Now().Add(-1 * time.Hour).Unix()

	// Insert expired key record in the database.
	InsertKey(expiredPrivKeyPEM, myTime)

}

func AuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Read private key from DB, get expired or non-expired based on query parameter.
	// Sign a JWT with the private key and return the JWT.

	// If the expired query parameter is set, use the expired key
	if expired, _ := strconv.ParseBool(r.URL.Query().Get("expired")); expired {
		myKid, myKey, myExp = GetKeys(true)
	} else {
		myKid, myKey, myExp = GetKeys(false)
	}

	// Create the token with the expiry
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"exp": myExp,
	})

	// Set the key ID header
	myKidString := strconv.Itoa(myKid)

	token.Header["kid"] = myKidString

	// Sign the token with the private key
	signedToken, err := token.SignedString(myKey)
	if err != nil {
		http.Error(w, "failed to sign token", http.StatusInternalServerError)
		return
	}

	_, _ = w.Write([]byte(signedToken))
}

type (
	JWKS struct {
		Keys []JWK `json:"keys"`
	}
	JWK struct {
		KID       string `json:"kid"`
		Algorithm string `json:"alg"`
		KeyType   string `json:"kty"`
		Use       string `json:"use"`
		N         string `json:"n"`
		E         string `json:"e"`
	}
)

func JWKSHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	base64URLEncode := func(b *big.Int) string {
		return base64.RawURLEncoding.EncodeToString(b.Bytes())
	}

	myKid, myKey, myExp = GetKeys(false)
	myKidString := strconv.Itoa(myKid)

	publicKey := myKey.Public().(*rsa.PublicKey)
	resp := JWKS{
		Keys: []JWK{
			{
				KID:       myKidString,
				Algorithm: "RS256",
				KeyType:   "RSA",
				Use:       "sig",
				N:         base64URLEncode(publicKey.N),
				E:         base64URLEncode(big.NewInt(int64(publicKey.E))),
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func CreateTable(db *sql.DB, createTableStatement string) {
	createStudentTableSQL := createTableStatement // SQL Statement for Create Table

	log.Println("Create keys table...")
	statement, err := db.Prepare(createStudentTableSQL) // Prepare SQL Statement
	if err != nil {
		log.Fatal(err.Error())
	}
	statement.Exec() // Execute SQL Statements
	log.Println("keys table created")
}

// func InsertKey(db *sql.DB, keyValue string, exp int64) {
func InsertKey(keyValue string, exp int64) {
	log.Println("Inserting key record ...")
	insertKeySQL := `INSERT INTO keys(key, exp) VALUES (?, ?)`

	statement, err := sqliteDatabase.Prepare(insertKeySQL) // Prepare statement to prevent SQL injection
	if err != nil {
		log.Fatalln(err.Error())
	}
	_, err = statement.Exec(keyValue, exp)
	if err != nil {
		log.Fatalln(err.Error())
	}
}

// func GetKeys(db *sql.DB, isExp bool) (ReturnKid int, ReturnKey *rsa.PrivateKey, ReturnExp int64) {
func GetKeys(isExp bool) (ReturnKid int, ReturnKey *rsa.PrivateKey, ReturnExp int64) {

	var row *sql.Rows
	var err error

	var (
		returnKid int
		returnKey *rsa.PrivateKey
		returnExp int64
	)

	// Get the valid key based on the expired query parameter.
	if isExp == false {
		row, err = sqliteDatabase.Query("SELECT kid, key, exp FROM keys WHERE kid = ? ORDER BY kid", 1)
		if err != nil {
			log.Fatal(err)
		}
	} else { // Get the expired key based on the expired query parameter.
		row, err = sqliteDatabase.Query("SELECT kid, key, exp FROM keys WHERE kid < ? ORDER BY kid", 2)
		if err != nil {
			log.Fatal(err)
		}
	}

	defer row.Close()
	for row.Next() { // Iterate and fetch the records from result cursor

		var kid int
		var key []byte
		var exp int64
		row.Scan(&kid, &key, &exp)

		deserializedKey, err := ParseRsaPrivateKeyFromPKCS1(key)
		if err != nil {
			log.Fatalln(err.Error())
		}

		returnKid = kid
		returnKey = deserializedKey
		returnExp = exp
	}

	return returnKid, returnKey, returnExp
}

func ExportRsaPrivateKeyAsPKCS1(privKey *rsa.PrivateKey) []byte {
	privkey_bytes := x509.MarshalPKCS1PrivateKey(privKey)

	return privkey_bytes
}

func ParseRsaPrivateKeyFromPKCS1(privPKCS1 []byte) (*rsa.PrivateKey, error) {

	priv, err := x509.ParsePKCS1PrivateKey(privPKCS1)
	if err != nil {
		return nil, err
	}
	return priv, nil
}
