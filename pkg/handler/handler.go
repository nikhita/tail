package handler

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"cloud.google.com/go/storage"

	"golang.org/x/oauth2"
	googleOAuth2 "golang.org/x/oauth2/google"

	"github.com/dghubble/gologin"
	"github.com/dghubble/gologin/google"
	"github.com/dghubble/sessions"
)

// TODO: update these values
const (
	sessionName    = "example-google-app"
	sessionSecret  = "example cookie signing secret"
	sessionUserKey = "googleID"
)

var pathChecker = regexp.MustCompile("logs/[a-zA-Z_-]+/[0-9]+/[ a-zA-Z_-]+/[0-9]+")

// sessionStore encodes and decodes session data stored in signed cookies
var sessionStore = sessions.NewCookieStore([]byte(sessionSecret), nil)

type prowBucketHandler struct {
	bucket       *storage.BucketHandle
	tmpDir       string
	clientID     string
	clientSecret string
	requestURL   string
}

func New(b *storage.BucketHandle, cacheDir, listenAddress, clientID, clientSecret string) *http.Server {
	bucketHandler := &prowBucketHandler{bucket: b, tmpDir: cacheDir, clientID: clientID, clientSecret: clientSecret}
	mux := &http.ServeMux{}
	mux.HandleFunc("/", bucketHandler.welcomeHandler)
	mux.HandleFunc("/logout", bucketHandler.logoutHandler)

	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "http://localhost:8080/google/callback", // TODO: change this!
		Endpoint:     googleOAuth2.Endpoint,
		Scopes:       []string{"email"},
	}

	stateConfig := gologin.DefaultCookieConfig
	mux.Handle("/google/login", google.StateHandler(stateConfig, google.LoginHandler(oauth2Config, nil)))
	mux.Handle("/google/callback", google.StateHandler(stateConfig, google.CallbackHandler(oauth2Config, bucketHandler.issueSession(), nil)))

	return &http.Server{
		Addr:         listenAddress,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
}

func (pbh *prowBucketHandler) welcomeHandler(resp http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.String(), "/logs") {
		// save the URl for logs so that we can redirect to this later
		pbh.requestURL = r.URL.String()

		if isLoggedIn(r) {
			pbh.handleLogRequest(resp, r)
			return
		}

		// if the user is not logged in, ask them to login
		page, _ := ioutil.ReadFile("login-page.html")
		fmt.Fprintf(resp, string(page))
	}
	resp.WriteHeader(http.StatusNotFound)
}

// isLoggedIn returns true if the user has a signed session cookie.
func isLoggedIn(req *http.Request) bool {
	if _, err := sessionStore.Get(req, sessionName); err == nil {
		return true
	}
	return false
}

// issueSession issues a cookie session after successful Google login
func (pbh *prowBucketHandler) issueSession() http.Handler {
	fn := func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		googleUser, err := google.UserFromContext(ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Issue a session to the user
		session := sessionStore.New(sessionName)
		session.Values[sessionUserKey] = googleUser.Id
		session.Save(w)

		if len(pbh.requestURL) == 0 {
			log.Fatalf("requestURL is empty") // TODO: handle this better
		}

		// Once the user is logged in, redirect to the logs URL
		http.Redirect(w, req, pbh.requestURL, http.StatusFound)
	}
	return http.HandlerFunc(fn)
}

// logoutHandler destroys the session on POSTs.
func (pbh *prowBucketHandler) logoutHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method == "POST" {
		sessionStore.Destroy(w, sessionName)
	}
	fmt.Fprint(w, `<p>You have successfully logged out!</p>`) // TODO: redirect to somewhere after logout?
}

func (pbh *prowBucketHandler) handleLogRequest(resp http.ResponseWriter, r *http.Request) {
	log.Printf("Got request for %s", r.URL.Path)
	if !pathChecker.MatchString(r.URL.Path) {
		resp.WriteHeader(http.StatusNotFound)
		return
	}

	bucketPath := strings.Replace(r.URL.Path, "/logs", "pr-logs/pull", 1)
	bucketPath = bucketPath + "/build-log.txt"
	cachePath := path.Join(pbh.tmpDir, strings.Replace(bucketPath, "/", "_", -1))
	cachePath = strings.Replace(cachePath, " ", "_", -1)
	if _, err := os.Stat(cachePath); err != nil {
		if !os.IsNotExist(err) {
			resp.WriteHeader(http.StatusInternalServerError)
			log.Printf("Failed to check if cache for file exists %s: %v", cachePath, err)
			return
		}

		log.Printf("Requesting file %s from bucket", bucketPath)
		obj := pbh.bucket.Object(bucketPath)
		reader, err := obj.NewReader(context.Background())
		if err != nil {
			resp.WriteHeader(http.StatusInternalServerError)
			log.Printf("Failed to get obj reader for %s: %v", bucketPath, err)
			return
		}
		data, err := ioutil.ReadAll(reader)
		if err != nil {
			resp.WriteHeader(http.StatusInternalServerError)
			log.Printf("Failed to read data for %s: %v", bucketPath, err)
			return
		}
		if err := reader.Close(); err != nil {
			resp.WriteHeader(http.StatusInternalServerError)
			log.Printf("failed to close reader for %s: %v", bucketPath, err)
			return
		}
		if err := ioutil.WriteFile(cachePath, data, 0600); err != nil {
			resp.WriteHeader(http.StatusInternalServerError)
			log.Printf("Failed to write cache file for %s: %v", cachePath, err)
			return
		}

	}

	data, err := ioutil.ReadFile(cachePath)
	if err != nil {
		resp.WriteHeader(http.StatusInternalServerError)
		log.Printf("Failed to read cache file for %s: %v", cachePath, err)
		return
	}

	if _, err := resp.Write(data); err != nil {
		log.Printf("failed to write data for %s: %v", bucketPath, err)
	}
}
