package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type person struct {
	Name string
	Age  int
}

func main() {

	log.Println("Launching server...")
	http.HandleFunc("/encode", encode)
	http.HandleFunc("/decode", decode)
	http.ListenAndServe(":8080", nil)
}

func encode(w http.ResponseWriter, r *http.Request) {

	people := []person{
		{Name: "Paul", Age: 51},
		{Name: "Mary", Age: 21},
	}
	xp, err := json.Marshal(people)
	if err != nil {
		log.Panicln(err)
	}
	log.Println(string(xp))
	err = json.NewEncoder(w).Encode(string(xp))
	if err != nil {
		log.Panicln("Bad data encoded", err)
	}

}

func decode(w http.ResponseWriter, r *http.Request) {

	var xp []person

	err := json.NewDecoder(r.Body).Decode(&xp)
	if err != nil {
		log.Println("Unable to decode", err)
	}
	log.Printf("Decoded people: %+v\n", xp)

}
