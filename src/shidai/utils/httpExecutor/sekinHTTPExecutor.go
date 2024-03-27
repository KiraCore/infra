package httpexecutor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"shidai/utils/osUtils"
	"time"
)

// TODO: make structs from iCaller && sCaller public
type SekaidKeysAdd struct {
	Address string `json:"address"`
	Keyring string `json:"keyring-backend"`
	Home    string `json:"home"`
	LogFmt  string `json:"log_format"`
	LogLvl  string `json:"log_level"`
	Output  string `json:"output"`
	Seed    string `json:"seed"`
	Trace   bool   `json:"trace"`
	Recover bool   `json:"recover"`
}

type SekaidStart struct {
	Home string `json:"home"`
}
type CommandRequest struct {
	Command string      `json:"command"`
	Args    interface{} `json:"args"`
}

// Executes post command for iCaller and sCaller
func ExecutePostCommand(address, port string, commandRequest CommandRequest) ([]byte, error) {
	check := osUtils.ValidatePort(port)
	if !check {
		return nil, fmt.Errorf("<%v> port is not valid", port)
	}
	// Convert your struct to JSON
	jsonData, err := json.Marshal(commandRequest)
	if err != nil {
		log.Println("Error marshaling JSON:", err)
		return nil, err
	}

	// Create a new POST request
	req, err := http.NewRequest("POST", fmt.Sprintf("http://%v:%v/api/execute", address, port), bytes.NewBuffer(jsonData))
	if err != nil {
		log.Println("Error creating request:", err)
		return nil, err
	}

	// Set the content type to application/json
	req.Header.Set("Content-Type", "application/json")

	// Perform the POST request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error making request:", err)
		return nil, err
	}
	defer resp.Body.Close()

	// Read and print the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error reading response body:", err)
		return nil, err
	}

	fmt.Println("Response:", string(body))
	return body, nil
}

func DoGetHttpQuery(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	const timeoutQuery = time.Second * 60

	ctx, cancel := context.WithTimeout(ctx, timeoutQuery)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		log.Printf("ERROR: Failed to create request: %s", err)
		return nil, err
	}

	log.Printf("DEBUG: Querying to '%s'", url)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("ERROR: Failed to send request: %s", err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ERROR: Failed to read response body: %s", err)
		return nil, err
	}

	// log.Printf(string(body))

	return body, nil
}
