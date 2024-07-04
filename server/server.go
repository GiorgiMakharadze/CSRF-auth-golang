package server

import (
	"log"
	"net/http"

	"github.com/GiorgiMakharadze/CSRF-auth-golang/middleware"
)

func StartServer(hostname, port string) error {
	host := hostname + ":" + port

	log.Printf("Listening on: %s", host)

	handler := middleware.NewHandler()
	
	http.Handle("/", handler)
	return http.ListenAndServe(host, nil)
}