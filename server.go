package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/duo-labs/webauthn.io/session"
	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gorilla/mux"
	"golang.org/x/net/http2"
)

var (
	webAuthn     *webauthn.WebAuthn
	userDB       *userdb
	sessionStore *session.Store
	tlsCert      = flag.String("tlsCert", "webauthn.crt", "TLS Certificate")
	tlsKey       = flag.String("tlsKey", "webauthn.key", "TLS Key")
	tlsCertChain = flag.String("tlsCertChain", "tls-ca.pem", "TLS CA Chain")
	RPID         = flag.String("rpid", "webauthn.domain.com", "Generally the domain name for your site")
	RPOrigin     = flag.String("rporigin", "https://webauthn.domain.com:8080", "The origin URL for WebAuthn requests")
	useTLS       = flag.Bool("useTLS", false, "Use TLS")
)

func main() {

	var err error
	flag.Parse()
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Acme Corp.",
		RPID:          *RPID,
		RPOrigin:      *RPOrigin,
	})

	if err != nil {
		log.Fatal("failed to create WebAuthn from config:", err)
	}

	userDB = DB()

	sessionStore, err = session.NewStore()
	if err != nil {
		log.Fatal("failed to create session store:", err)
	}

	r := mux.NewRouter()

	r.HandleFunc("/register/begin", beginRegistration).Methods("POST")
	r.HandleFunc("/register/finish/{username}", finishRegistration).Methods("POST")
	r.HandleFunc("/login/begin", beginLogin).Methods("POST")
	r.HandleFunc("/login/finish/{username}", finishLogin).Methods("POST")

	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./")))
	serverAddress := ":8080"

	if *useTLS {
		clientCaCert, err := ioutil.ReadFile(*tlsCertChain)
		if err != nil {
			log.Fatalf("Could not read CA %v", err)
		}
		clientCaCertPool := x509.NewCertPool()
		clientCaCertPool.AppendCertsFromPEM(clientCaCert)

		tlsConfig := &tls.Config{
			ClientAuth: tls.NoClientCert,
			ClientCAs:  clientCaCertPool,
		}

		server := &http.Server{
			Addr:      serverAddress,
			Handler:   r,
			TLSConfig: tlsConfig,
		}
		http2.ConfigureServer(server, &http2.Server{})

		log.Println("starting server at", serverAddress)
		log.Fatal(server.ListenAndServeTLS(*tlsCert, *tlsKey))
	} else {
		server := &http.Server{
			Addr:    serverAddress,
			Handler: r,
		}
		http2.ConfigureServer(server, &http2.Server{})

		log.Println("starting server at", serverAddress)
		log.Fatal(server.ListenAndServe())
	}
}

func beginRegistration(w http.ResponseWriter, r *http.Request) {

	// get username/friendly name
	username := r.FormValue("username")
	if username == "" {
		jsonResponse(w, "must supply a valid username i.e. foo@bar.com", http.StatusBadRequest)
		return
	}
	password := r.FormValue("password")
	if password == "" {
		jsonResponse(w, "must supply a password", http.StatusBadRequest)
		return
	}
	// get user
	user, err := userDB.GetUser(username)
	// user doesn't exist, create new user
	if err != nil {
		displayName := strings.Split(username, "@")[0]
		user = NewUser(username, password, displayName)
		userDB.PutUser(user)
	}

	requireResidentKey := false
	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = user.CredentialExcludeList()
		credCreationOpts.AuthenticatorSelection = protocol.AuthenticatorSelection{
			RequireResidentKey: &requireResidentKey,
		}
	}

	// generate PublicKeyCredentialCreationOptions, session data
	options, sessionData, err := webAuthn.BeginRegistration(
		user,
		registerOptions,
	)

	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	b, err := json.MarshalIndent(sessionData, "", "  ")
	if err != nil {
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("sessionData: \n%s", string(b))

	// store session data as marshaled JSON
	err = sessionStore.SaveWebauthnSession("registration", sessionData, r, w)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	b, err = json.MarshalIndent(options, "", "  ")
	if err != nil {
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("options: \n%s", string(b))
	jsonResponse(w, options, http.StatusOK)
}

func finishRegistration(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	// get user
	user, err := userDB.GetUser(username)
	// user doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// load the session data
	sessionData, err := sessionStore.GetWebauthnSession("registration", r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	credential, err := webAuthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	b, err := json.MarshalIndent(credential, "", "  ")
	if err != nil {
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("credential: \n%s", string(b))
	user.AddCredential(*credential)

	jsonResponse(w, "Registration Success", http.StatusOK)
}

func beginLogin(w http.ResponseWriter, r *http.Request) {

	username := r.FormValue("username")
	if username == "" {
		jsonResponse(w, "must supply a valid username i.e. foo@bar.com", http.StatusBadRequest)
		return
	}
	password := r.FormValue("password")
	if password == "" {
		jsonResponse(w, "must supply a password", http.StatusBadRequest)
		return
	}

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !user.VerifyPassword(password) {
		jsonResponse(w, "invalid password", http.StatusBadRequest)
		return
	}
	// generate PublicKeyCredentialRequestOptions, session data
	options, sessionData, err := webAuthn.BeginLogin(user)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// store session data as marshaled JSON
	err = sessionStore.SaveWebauthnSession("authentication", sessionData, r, w)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	b, err := json.Marshal(options)
	if err != nil {
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("Login Options: \n%s", string(b))
	jsonResponse(w, options, http.StatusOK)
}

func finishLogin(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// load the session data
	sessionData, err := sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// in an actual implementation, we should perform additional checks on
	// the returned 'credential', i.e. check 'credential.Authenticator.CloneWarning'
	// and then increment the credentials counter
	_, err = webAuthn.FinishLogin(user, sessionData, r)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// handle successful login
	jsonResponse(w, "Login Success", http.StatusOK)
}

// from: https://github.com/duo-labs/webauthn.io/blob/3f03b482d21476f6b9fb82b2bf1458ff61a61d41/server/response.go#L15
func jsonResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}
