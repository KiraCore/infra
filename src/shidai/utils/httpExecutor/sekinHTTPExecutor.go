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

type InterxInit struct {
	AddrBook                    *string `json:"addrbook,omitempty"`
	CacheDir                    *string `json:"cache_dir,omitempty"`
	CachingDuration             *int    `json:"caching_duration,omitempty"`
	DownloadFileSizeLimitation  *string `json:"download_file_size_limitation,omitempty"`
	FaucetAmounts               *string `json:"faucet_amounts,omitempty"`
	FaucetMinimumAmounts        *string `json:"faucet_minimum_amounts,omitempty"`
	FaucetMnemonic              *string `json:"faucet_mnemonic,omitempty"`
	FaucetTimeLimit             *int    `json:"faucet_time_limit,omitempty"`
	FeeAmounts                  *string `json:"fee_amounts,omitempty"`
	Grpc                        *string `json:"grpc"`
	HaltedAvgBlockTimes         *int    `json:"halted_avg_block_times,omitempty"`
	Home                        *string `json:"home"`
	MaxCacheSize                *string `json:"max_cache_size,omitempty"`
	NodeDiscoveryInterxPort     *string `json:"node_discovery_interx_port,omitempty"`
	NodeDiscoveryTendermintPort *string `json:"node_discovery_tendermint_port,omitempty"`
	NodeDiscoveryTimeout        *string `json:"node_discovery_timeout,omitempty"`
	NodeDiscoveryUseHttps       *bool   `json:"node_discovery_use_https,omitempty"`
	NodeKey                     *string `json:"node_key,omitempty"`
	NodeType                    *string `json:"node_type,omitempty"`
	Port                        *string `json:"port"`
	Rpc                         *string `json:"rpc"`
	SeedNodeID                  *string `json:"seed_node_id,omitempty"`
	SentryNodeID                *string `json:"sentry_node_id,omitempty"`
	ServeHttps                  *bool   `json:"serve_https,omitempty"`
	SigningMnemonic             *string `json:"signing_mnemonic,omitempty"`
	SnapshotInterval            *int    `json:"snapshot_interval,omitempty"`
	SnapshotNodeID              *string `json:"snapshot_node_id,omitempty"`
	StatusSync                  *int    `json:"status_sync,omitempty"`
	TxModes                     *string `json:"tx_modes,omitempty"`
	ValidatorNodeID             *string `json:"validator_node_id,omitempty"`
}

type InterxStart struct {
	Home string `json:"home,omitempty"`
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
