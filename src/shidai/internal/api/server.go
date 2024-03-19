package api

import (
	"net/http"

	"shidai/internal/commands"
)

func Serve() {
	http.HandleFunc("/api/execute", commands.ExecuteCommandHandler)
	http.ListenAndServe(":8282", nil)

}
