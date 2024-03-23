package tomlEditor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"shidai/utils/config"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

type TomlValue struct {
	Tag   string
	Name  string
	Value string
}

const endpointPubP2PList string = "api/pub_p2p_list?peers_only=true"
const endpointStatus string = "status"

func GetStandardConfigPack() []TomlValue {

	cfg := config.DefaultKiraConfig()

	configs := []TomlValue{
		// # CFG [base]
		{Tag: "", Name: "moniker", Value: cfg.Moniker},
		{Tag: "", Name: "fast_sync", Value: "true"},
		// # CFG [FASTSYNC]
		{Tag: "fastsync", Name: "version", Value: "v1"},
		// # CFG [MEMPOOL]
		{Tag: "mempool", Name: "max_txs_bytes", Value: "131072000"},
		{Tag: "mempool", Name: "max_tx_bytes", Value: "131072"},
		// # CFG [CONSENSUS]
		{Tag: "consensus", Name: "timeout_commit", Value: "10000ms"},
		{Tag: "consensus", Name: "create_empty_blocks_interval", Value: "20s"},
		{Tag: "consensus", Name: "skip_timeout_commit", Value: "false"},
		// # CFG [INSTRUMENTATION]
		{Tag: "instrumentation", Name: "prometheus", Value: "true"},
		// # CFG [P2P]
		{Tag: "p2p", Name: "pex", Value: "true"},
		{Tag: "p2p", Name: "private_peer_ids", Value: ""},
		{Tag: "p2p", Name: "unconditional_peer_ids", Value: ""},
		{Tag: "p2p", Name: "persistent_peers", Value: ""},
		{Tag: "p2p", Name: "seeds", Value: ""},
		{Tag: "p2p", Name: "laddr", Value: fmt.Sprintf("tcp://0.0.0.0:%s", cfg.P2PPort)},
		{Tag: "p2p", Name: "seed_mode", Value: "false"},
		{Tag: "p2p", Name: "max_num_outbound_peers", Value: "32"},
		{Tag: "p2p", Name: "max_num_inbound_peers", Value: "128"},
		{Tag: "p2p", Name: "send_rate", Value: "65536000"},
		{Tag: "p2p", Name: "recv_rate", Value: "65536000"},
		{Tag: "p2p", Name: "max_packet_msg_payload_size", Value: "131072"},
		{Tag: "p2p", Name: "handshake_timeout", Value: "60s"},
		{Tag: "p2p", Name: "dial_timeout", Value: "30s"},
		{Tag: "p2p", Name: "allow_duplicate_ip", Value: "true"},
		{Tag: "p2p", Name: "addr_book_strict", Value: "true"},
		// # CFG [RPC]
		{Tag: "rpc", Name: "laddr", Value: fmt.Sprintf("tcp://0.0.0.0:%s", cfg.RpcPort)},
		{Tag: "rpc", Name: "cors_allowed_origins", Value: "[ \"*\" ]"},
	}

	return configs
}

type networkInfo struct {
	NetworkName string
	NodeID      string
	BlockHeight string
	Seeds       []string
}

func RetrieveNetworkInformation(ctx context.Context, client *http.Client, tc *TargetSeedKiraConfig) (*networkInfo, error) {

	statusResponse, err := getSekaidStatus(ctx, client, tc.IpAddress, tc.SekaidRPCPort)
	if err != nil {
		return nil, fmt.Errorf("getting sekaid status: %w", err)
	}

	// TODO: rewrite for 26657/netInfo instead of interx pub_p2p_list
	pupP2PListResponse, err := getPubP2PList(ctx, client, tc.IpAddress, tc.InterxPort)
	if err != nil {
		return nil, fmt.Errorf("getting sekaid public P2P list: %w", err)
	}

	listOfSeeds, err := parsePubP2PListResponse(ctx, pupP2PListResponse)
	if err != nil {
		return nil, fmt.Errorf("parsing sekaid public P2P list %w", err)
	}
	if len(listOfSeeds) == 0 {
		log.Printf("ERROR: List of seeds is empty, the trusted seed will be used")
		listOfSeeds = []string{fmt.Sprintf("tcp://%s@%s:%s", statusResponse.Result.NodeInfo.ID, tc.IpAddress, tc.SekaidP2PPort)}
	}

	return &networkInfo{
		NetworkName: statusResponse.Result.NodeInfo.Network,
		NodeID:      statusResponse.Result.NodeInfo.ID,
		BlockHeight: statusResponse.Result.SyncInfo.LatestBlockHeight,
		Seeds:       listOfSeeds,
	}, nil
}

func getSekaidStatus(ctx context.Context, client *http.Client, ipAddress, rpcPort string) (*ResponseSekaidStatus, error) {

	url := fmt.Sprintf("http://%s:%s/%s", ipAddress, rpcPort, endpointStatus)

	body, err := doGetHttpQuery(ctx, client, url)
	if err != nil {
		log.Printf("ERROR: Querying error: %s", err)
		return nil, err
	}

	var response *ResponseSekaidStatus
	err = json.Unmarshal(body, &response)
	if err != nil {
		log.Printf("ERROR: Can't parse JSON response: %s", err)
		return nil, err
	}

	return response, nil
}

func doGetHttpQuery(ctx context.Context, client *http.Client, url string) ([]byte, error) {

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

	log.Printf(string(body))

	return body, nil
}

type ResponseSekaidStatus struct {
	Result struct {
		NodeInfo struct {
			ID      string `json:"id"`
			Network string `json:"network"`
		} `json:"node_info"`
		SyncInfo struct {
			LatestBlockHeight string    `json:"latest_block_height"`
			LatestBlockTime   time.Time `json:"latest_block_time"`
			CatchingUp        bool      `json:"catching_up"`
		} `json:"sync_info"`
	} `json:"result"`
}

func getPubP2PList(ctx context.Context, client *http.Client, ipAddress, rpcPort string) ([]byte, error) {

	url := fmt.Sprintf("http://%s:%s/%s", ipAddress, rpcPort, endpointPubP2PList)

	body, err := doGetHttpQuery(ctx, client, url)
	if err != nil {
		log.Printf("ERROR: Querying error: %s", err)
		return nil, err
	}

	return body, nil
}

func parsePubP2PListResponse(ctx context.Context, seedsResponse []byte) ([]string, error) {

	if len(seedsResponse) == 0 {
		log.Printf("WARNING: The list of public seeds is not available")
		return nil, nil
	}

	linesOfPeers := strings.Split(string(seedsResponse), "\n")
	listOfSeeds := make([]string, 0)

	for _, line := range linesOfPeers {
		formattedSeed := fmt.Sprintf("tcp://%s", line)
		log.Printf("Debug: Got seed: %s", formattedSeed)
		listOfSeeds = append(listOfSeeds, formattedSeed)
	}

	return listOfSeeds, nil
}

type TargetSeedKiraConfig struct {
	IpAddress     string
	InterxPort    string
	SekaidRPCPort string
	SekaidP2PPort string
}

func GetConfigsBasedOnSeed(ctx context.Context, client *http.Client, netInfo *networkInfo, tc *TargetSeedKiraConfig) ([]config.TomlValue, error) {
	configValues := make([]config.TomlValue, 0)

	configValues = append(configValues, config.TomlValue{Tag: "p2p", Name: "seeds", Value: strings.Join(netInfo.Seeds, ",")})

	listOfRPC, err := parseRPCfromSeedsList(netInfo.Seeds, tc)
	if err != nil {
		return nil, fmt.Errorf("parsing RPCs from seeds list %w", err)
	}

	syncInfo, err := getSyncInfo(ctx, client, listOfRPC, netInfo.BlockHeight)
	if err != nil {
		return nil, fmt.Errorf("getting sync information %w", err)
	}

	if syncInfo != nil {
		configValues = append(configValues, config.TomlValue{Tag: "statesync", Name: "trust_hash", Value: syncInfo.trustHashBlock})
		configValues = append(configValues, config.TomlValue{Tag: "statesync", Name: "trust_height", Value: syncInfo.trustHeightBlock})
		configValues = append(configValues, config.TomlValue{Tag: "statesync", Name: "rpc_servers", Value: strings.Join(syncInfo.rpcServers, ",")})
		configValues = append(configValues, config.TomlValue{Tag: "statesync", Name: "trust_period", Value: "168h0m0s"})
		configValues = append(configValues, config.TomlValue{Tag: "statesync", Name: "enable", Value: "true"})
		configValues = append(configValues, config.TomlValue{Tag: "statesync", Name: "temp_dir", Value: "/tmp"})
	}

	return configValues, nil
}

func parseRPCfromSeedsList(seeds []string, tc *TargetSeedKiraConfig) ([]string, error) {

	listOfRPCs := make([]string, 0)

	for _, seed := range seeds {
		// tcp://23ca3770ae3874ac8f5a6f84a5cfaa1b39e49fc9@128.140.86.241:26656 -> 128.140.86.241:26657
		parts := strings.Split(seed, "@")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid seed format")
		}

		ipAndPort := strings.Split(parts[1], ":")
		if len(ipAndPort) != 2 {
			return nil, fmt.Errorf("invalid port format")
		}

		rpc := fmt.Sprintf("%s:%s", ipAndPort[0], tc.SekaidRPCPort)
		log.Printf("Adding rpc to list: %s", rpc)
		listOfRPCs = append(listOfRPCs, rpc)
	}

	return listOfRPCs, nil
}

type syncInfo struct {
	rpcServers       []string
	trustHeightBlock string
	trustHashBlock   string
}

func getSyncInfo(ctx context.Context, client *http.Client, listOfRPC []string, minHeight string) (*syncInfo, error) {

	resultSyncInfo := &syncInfo{
		rpcServers:       []string{},
		trustHeightBlock: "",
		trustHashBlock:   "",
	}

	for _, rpcServer := range listOfRPC {
		responseBlock, err := getBlockInfo(ctx, client, rpcServer, minHeight)
		if err != nil {
			log.Printf("Can't get block information from RPC '%s'", rpcServer)
			continue
		}

		if responseBlock.Result.Block.Header.Height != minHeight {
			log.Printf("RPC (%s) height is '%s', but expected '%s'", rpcServer, responseBlock.Result.Block.Header.Height, minHeight)
			continue
		}

		if responseBlock.Result.BlockID.Hash != resultSyncInfo.trustHashBlock && resultSyncInfo.trustHashBlock != "" {
			log.Printf("RPC (%s) hash is '%s', but expected '%s'", rpcServer, responseBlock.Result.BlockID.Hash, resultSyncInfo.trustHashBlock)
			continue
		}

		resultSyncInfo.trustHashBlock = responseBlock.Result.BlockID.Hash
		resultSyncInfo.trustHeightBlock = minHeight

		log.Printf("Adding RPC (%s) to RPC connection list", rpcServer)
		resultSyncInfo.rpcServers = append(resultSyncInfo.rpcServers, rpcServer)
	}

	if len(resultSyncInfo.rpcServers) < 2 {
		log.Printf("Sync is NOT possible (not enough RPC servers)")
		return nil, nil
	}

	log.Printf("%+v", resultSyncInfo)
	return resultSyncInfo, nil
}

type ResponseBlock struct {
	Result struct {
		BlockID struct {
			Hash string `json:"hash"`
		} `json:"block_id"`
		Block struct {
			Header struct {
				Height string `json:"height"`
			} `json:"header"`
		} `json:"block"`
	} `json:"result"`
}

func getBlockInfo(ctx context.Context, client *http.Client, rpcServer, blockHeight string) (*ResponseBlock, error) {
	endpointBlock := fmt.Sprintf("block?height=%s", blockHeight)

	url := fmt.Sprintf("http://%s/%s", rpcServer, endpointBlock)
	body, err := doGetHttpQuery(ctx, client, url)
	if err != nil {
		return nil, fmt.Errorf("can't reach block response %w", err)
	}

	var response *ResponseBlock
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, fmt.Errorf("can't parse JSON response %w", err)
	}

	return response, nil
}