package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var myConfig = &oauth2.Config{
	ClientID:     "changeme",
	ClientSecret: "changeme",
	Endpoint:     github.Endpoint,
}

var myStateMap = map[uuid.UUID]time.Time{}

func main() {
	log.Println("Launching server on port 8080...")
	http.HandleFunc("/", index)
	http.HandleFunc("/oauth/login", oauthLogin)
	http.HandleFunc("/oauth/receive", oauthReceive)
	http.ListenAndServe(":8080", nil)
}

func index(w http.ResponseWriter, r *http.Request) {

	html := `
	<html>
		<head>
			<title>Testing Oauth2</title>
		</head>
		<body>
			<form action="/oauth/login" method="post">	
			<input type="submit" value="Login with Github">
	</form>
		</body>
	</html>	
	`
	io.WriteString(w, html)
	return
}

func oauthLogin(w http.ResponseWriter, r *http.Request) {
	myUUID, err := uuid.NewV4()
	if err != nil {
		log.Fatalf("Error generating uuid %v", err)
		return
	}
	myStateMap[myUUID] = time.Now().Add(time.Hour)
	url := myConfig.AuthCodeURL(fmt.Sprintf("%s", myUUID))
	http.Redirect(w, r, url, http.StatusSeeOther)
	return
}

func oauthReceive(w http.ResponseWriter, r *http.Request) {
}
