package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"shidai/internal/registry"
)

type CommandRequest struct {
	Command string                 `json:"command"`
	Args    map[string]interface{} `json:"args"`
}

func ExecuteCommandHandler(w http.ResponseWriter, r *http.Request) {
	var req CommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	slog.Info("Handle", "command", req.Command, "arguments", req.Args)

	executor, exists := registry.GetCommandExecutor(req.Command)
	if !exists {
		slog.Error("Not supported", "command", req.Command)

		http.Error(w, "Command not supported", http.StatusNotFound)
		return
	}

	if err := executor.Execute( /*config*/ ); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Info("SUCCESS!", "command", req.Command)

	json.NewEncoder(w).Encode(map[string]string{"status": "success"}) //nolint:errcheck
}
