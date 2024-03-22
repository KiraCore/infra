package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"
)

func postCommand(command string, args map[string]interface{}) error {
	slog.Info("POSTing the next command", "command", command, "args", args)
	body, err := json.Marshal(map[string]interface{}{
		"command": command,
		"args":    args,
	})
	if err != nil {
		slog.Error("marshaling the next command", "error", err)
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// TODO change URL based on config
	req, err := http.NewRequestWithContext(ctx, "POST", "http://sekaid_rpc:8080/api/execute", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		if errors.Is(err, io.EOF) && command == "start" {
			// Log that the start command was sent, and EOF is expected
			slog.Info("Start command issued, server process is expected to restart", "command", command)
			return nil // Treat this specific case as success
		} else {
			// For all other errors, log and return the error as usual
			slog.Error("Error making request", "command", command, "error", err)
			return err
		}
	}
	defer response.Body.Close()

	// TODO change error handling based not only on error type but on HTTP status code
	slog.Debug("Got response", "status code", response.StatusCode, "status", response.Status)

	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	bodyString := string(bodyBytes)
	slog.Info("Response:", "body", bodyString)

	return nil
}
