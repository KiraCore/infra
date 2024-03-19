package api

import (
	"net/http"

	"github.com/KiraCore/sekin/src/shidai/internal/commands"
)

func Serve() {
	http.HandleFunc("/api/execute", commands.ExecuteCommandHandler)
	http.ListenAndServe(":8282", nil)

}
