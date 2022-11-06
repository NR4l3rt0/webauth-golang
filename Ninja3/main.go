package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var ctx = context.Background()
var myConfig = &oauth2.Config{
	ClientID:     "changeme",
	ClientSecret: "changeme",
	Endpoint:     github.Endpoint,
}

type customClaims struct {
	*jwt.StandardClaims
	SID string
}

type ghUser struct {
	Login        string
	Id           int
	Bio          string
	Public_repos int
}

var myStateMap = map[uuid.UUID]time.Time{}
var oauthConnections = map[string]string{}

var key = []byte("Thisismykey")

func main() {
	log.Println("Launching server on port 8080...")
	http.HandleFunc("/", index)
	http.HandleFunc("/oauth/login", oauthLogin)
	http.HandleFunc("/partial-register", partialRegister)
	http.HandleFunc("/oauth/register", oauthRegister)
	http.HandleFunc("/oauth/receive", oauthReceive)
	http.HandleFunc("/get-uid-from-token", getUIDFromToken)
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
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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
	state := r.FormValue("state")
	code := r.FormValue("code")

	if state == "" || code == "" {
		http.Error(w, "State or code not valid", http.StatusInternalServerError)
		return
	}

	myUUID, err := uuid.FromString(state)
	if err != nil {
		http.Error(w, "Error while taking the UUID", http.StatusInternalServerError)
		return
	}
	if myStateMap[myUUID].Before(time.Now()) {
		http.Error(w, "State invalid", http.StatusRequestTimeout)
		return
	}

	token, err := myConfig.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Error in the exchange", http.StatusInternalServerError)
		return
	}

	ts := myConfig.TokenSource(ctx, token)
	client := oauth2.NewClient(ctx, ts)

	res, err := client.Get("https://api.github.com/users/NR4l3rt0")
	if err != nil {
		http.Error(w, fmt.Sprintf("Error while fetching data: %s", err), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()
	response, err := ioutil.ReadAll(res.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error while reading data: %s", err), http.StatusInternalServerError)
		return
	}
	// ReadAll does check network issue but not request status
	if res.StatusCode < 200 || res.StatusCode > 299 {
		msg := url.QueryEscape("Not successful response code: " + string(response))
		http.Redirect(w, r, "?msg="+msg, http.StatusSeeOther)
		return
	}
	//io.WriteString(w, string(response))
	var myUser ghUser
	json.Unmarshal(response, &myUser)

	// if user not present locally, generate an entry in our "system"
	if _, ok := oauthConnections[fmt.Sprint(myUser.Id)]; !ok {
		/*user_id := url.QueryEscape(fmt.Sprintf("%s", fmt.Sprint(myUser.Id)))
		username := url.QueryEscape("Peter")
		http.Redirect(w, r, "/partial-register?user_id="+user_id+"&username="+username, http.StatusSeeOther) */
		queryParams := url.Values{}
		queryParams.Add("user_id", fmt.Sprintf("%s", fmt.Sprint(myUser.Id)))
		queryParams.Add("username", "Pet")
		http.Redirect(w, r, "/partial-register?"+queryParams.Encode(), http.StatusSeeOther)
		return
	} else {
		// Present user simulation flow
		myUUID, _ = uuid.NewV4()
		oauthConnections[fmt.Sprint(myUser.Id)] = myUUID.String()
		myUser.createSession(w, r)
		return
	}
}

func (u ghUser) createSession(w http.ResponseWriter, r *http.Request) {

	token, err := createToken(u)
	if err != nil {
		//log.Println("", err)
		msg := url.QueryEscape(fmt.Sprintf("could not create token: %v", err))
		http.Redirect(w, r, "?msg="+msg, http.StatusSeeOther)
		return
	}

	myCookie := http.Cookie{
		//Name:  "session_id",
		Name:  "seSSion_id",
		Value: token,
		//Path:  "/oauth",
		Path: "/",
	}

	http.SetCookie(w, &myCookie)
	//msg := url.QueryEscape("user is logged in!")
	//http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
	http.Redirect(w, r, "/", http.StatusSeeOther)
	return
}

func createToken(u ghUser) (string, error) {

	cc := customClaims{
		StandardClaims: &jwt.StandardClaims{
			ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
		},
		SID: fmt.Sprint(u.Id),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, cc)
	st, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("Could not sign token %w", err)
	}
	return st, nil

}

func partialRegister(w http.ResponseWriter, r *http.Request) {
	html := fmt.Sprintf(`
	<html>
		<head>
			<title>Register Oauth2</title>
		</head>
		<body>
			<form action="/oauth/register" method="post">	
				<input type="hidden" id="user_id" name="user_id" value="%s">
				<label for="username">Username:</label>
				<input type="text" id="username" name="username" value="%s">
				<input type="tel" name="phone" placeholder="123-1234-1234">
				<input type="checkbox" id="terms" name="terms">
				<label for="terms">Agree with terms</label>
				<input type="submit" value="Sign up">
			</form>
		</body>
	</html>	
	`, r.URL.Query()["user_id"][0], r.URL.Query()["username"][0])
	io.WriteString(w, html)
	return
}

func oauthRegister(w http.ResponseWriter, r *http.Request) {
	user_id := r.FormValue("user_id")
	/*username := r.FormValue("username")
	terms := r.FormValue("terms")
	phone := r.FormValue("phone")
	fmt.Fprint(w, username, user_id, terms, phone)*/
	uID, err := strconv.Atoi(user_id)
	if err != nil {
		http.Error(w, "Error in user_id", http.StatusInternalServerError)
		return
	}
	myUser := ghUser{Id: uID}
	myUser.createSession(w, r)
	return
}

func parseToken(st string) string {
	token, err := jwt.ParseWithClaims(st, &customClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			log.Fatalln("/?err=comparing-alg", http.StatusInternalServerError)
			return nil, errors.New("Not the same Alg")
		}
		return key, nil
	})
	if err != nil {
		log.Fatalln("/?err=possible-hack", http.StatusInternalServerError)
		return ""
	}

	if !token.Valid {
		log.Fatalln("/?err=invalid-token", http.StatusInternalServerError)
		return ""
	}
	return fmt.Sprint(token.Claims.(*customClaims).SID)
}

func getUIDFromToken(w http.ResponseWriter, r *http.Request) {
	myCookie, err := r.Cookie("seSSion_id")
	if err != nil {
		http.Error(w, "Cookie could not be taken", http.StatusInternalServerError)
		return
	}
	uID := parseToken(myCookie.Value)
	if uID == "" {
		http.Error(w, "Token could not be parsed", http.StatusInternalServerError)
		return
	}
	io.WriteString(w, uID)
	return
}
