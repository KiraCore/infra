package api

import (
	"log/slog"
	"net/http"
	"os"

	"shidai/internal/executors"
	"shidai/internal/handler"
	"shidai/internal/registry"
)

func Serve() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
	slog.SetDefault(logger)

	slog.Info("Registration of the Init Executor using registry", "command", "init")
	registry.RegisterExecutor("init", executors.NewInitExecutor(map[string]interface{}{}))

	slog.Info("Listening on ':8282' for '/api/execute'")
	http.HandleFunc("/api/execute", handler.ExecuteCommandHandler)
	http.ListenAndServe(":8282", nil) //nolint:errcheck
}
