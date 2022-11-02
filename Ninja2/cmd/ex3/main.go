// entry point
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

type user struct {
	Name     string
	Password []byte
}

type myCustomClaims struct {
	SessionId string
	*jwt.RegisteredClaims
}

var registeredUsers map[uuid.UUID]user

func main() {

	registeredUsers = make(map[uuid.UUID]user)

	http.HandleFunc("/", showHome)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/check", check)
	http.HandleFunc("/createToken", createToken)
	http.HandleFunc("/users", displayUsers)
	log.Println("Launching server on port 8080...")
	http.ListenAndServe(":8080", nil)
}

func showHome(w http.ResponseWriter, r *http.Request) {
	html := ` <html>	
			<head>
				<title>My Go test</title>
			</head>
			<body>
				<h1>User data</h1>
				<form action="/register" method="post">
					<label for="username">Username:</label><br>
					<input type="text" id="username" name="username" /><br>
					<label for="password">Password:</label><br>
				<input type="password" id="password" name="password" /><br>
					<input type="submit" value="submit" />
					<input type="reset" />
				</form>
			</body>
		  </html>`
	_, err := io.WriteString(w, html)
	if err != nil {
		log.Fatalln("Unable to serve the main page")
	}
}

func register(w http.ResponseWriter, r *http.Request) {
	myPass := r.FormValue("password")
	// Minimal healthckeck
	if myPass == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	h, err := bcrypt.GenerateFromPassword([]byte(myPass), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalln("Unable to generate hash")
	}

	myUser := user{
		Name:     r.FormValue("username"),
		Password: h,
	}

	err = AddUser(myUser)
	if err != nil {
		log.Panicln("Unable to add users")
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)

}

// AddUser add a user to the store
func AddUser(u user) error {

	myUUID, err := uuid.NewV4()
	if err != nil {
		log.Fatalln("UUID could not be generated")
	}
	registeredUsers[myUUID] = u
	return nil
}

func displayUsers(w http.ResponseWriter, r *http.Request) {

	var myList string
	if len(registeredUsers) != 0 {
		myList = "<html><head></head><body><ul>"
		for k, v := range registeredUsers {
			myList += fmt.Sprintf("<li>ID: %v, User: %+v</li>", k, v)
		}
		myList += "</ul></body></html>"
	} else {
		io.WriteString(w, fmt.Sprintf("<html><head></head><body><h2>There are not users yet. Try a bit later again!</h2></body></html>"))
		return
	}
	io.WriteString(w, myList)
}

func login(w http.ResponseWriter, r *http.Request) {
	html := ` <html>	
			<head>
				<title>Login page</title>
			</head>
			<body>
				<h1>Login</h1>
				<form action="/check" method="post">
					<label for="username">Username:</label><br>
					<input type="text" id="username" name="username" /><br>
					<label for="password">Password:</label><br>
				<input type="password" id="password" name="password" /><br>
					<input type="submit" value="submit" />
					<input type="reset" />
				</form>
			</body>
		  </html>`
	_, err := io.WriteString(w, html)
	if err != nil {
		log.Fatalln("Unable to serve the login page")
	}
}

func check(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	pass := r.FormValue("password")
	if username == "" || pass == "" {
		http.Error(w, "Fields cannot be blank", http.StatusBadRequest)
	}

	userUUID := getUser(username)
	if storedUser, ok := registeredUsers[userUUID]; ok {
		if err := bcrypt.CompareHashAndPassword(storedUser.Password, []byte(pass)); err == nil {
			http.Error(w, "User logged in", http.StatusOK)
		} else {
			http.Error(w, "User NOT logged in", http.StatusNetworkAuthenticationRequired)
		}
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
	return

}

// getUser will return the UUID of an existent user, nil otherwise
func getUser(username string) uuid.UUID {

	for k, v := range registeredUsers {
		if username == v.Name {
			return k
		}
	}
	return [16]byte{}
}

func createToken(w http.ResponseWriter, r *http.Request) {
	myKey := []byte("Thisismykey")
	mySessionCookie, err := r.Cookie("session_id")
	if err != nil {
		mySessionCookie = &http.Cookie{Name: "session_id", Value: "1234123412341234"}
	}

	myClaim := myCustomClaims{
		mySessionCookie.Value,
		&jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Unix(1516239022, 0)),
			Issuer:    "myIssuer",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, myClaim)

	signedSignature, err := token.SignedString(myKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error while creating the signed signature: %v", err), http.StatusInternalServerError)
	}
	io.WriteString(w, signedSignature)
	return
}

func parseToken(ss string) {
	myKey := []byte("Thisismykey")

	token, err := jwt.ParseWithClaims(ss, &myCustomClaims{}, func(ss *jwt.Token) (interface{}, error) {
		if ss.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("Not the same Method in signature")
		}
		return ss, nil
	})
	if err != nil {
		log.Fatal("Possible hack")
	}
	claims := token.(*myCustomClaims)
	io.WriteString(w, claims)
	return
}
