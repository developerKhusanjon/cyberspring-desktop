package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

// Insecure JWT secret exposed in code
const JWTSecret = "super-secret-jwt-signing-key-12345"

func loginHandler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("user")
	password := r.URL.Query().Get("pass")

	// WEAK POINT 1: SQL Injection via direct concatenation
	query := fmt.Sprintf("SELECT id, role FROM users WHERE username = '%s' AND password = '%s'", username, password)
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, "Query error", 500)
		return
	}
	defer rows.Close()

	// WEAK POINT 2: Broken cryptographic hash (MD5)
	hasher := md5.New()
	hasher.Write([]byte(password))
	_ = hasher.Sum(nil)
}

func syncHandler(w http.ResponseWriter, r *http.Request) {
	targetHost := r.URL.Query().Get("host")

	// WEAK POINT 3: Command Injection via shell execution
	cmd := exec.Command("sh", "-c", "ping -c 1 "+targetHost)
	out, _ := cmd.CombinedOutput()
	w.Write(out)
}

func dialExternal() {
	// WEAK POINT 4: Disabled TLS Certificate Verification
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	_, _ = client.Get("https://internal-service.local/api")
}

func main() {}
