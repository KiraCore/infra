package tomlEditor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"shidai/utils/config"
	httpexecutor "shidai/utils/httpExecutor"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const endpointPubP2PList string = "api/pub_p2p_list?peers_only=true"
const endpointStatus string = "status"

type networkInfo struct {
	NetworkName string
	NodeID      string
	BlockHeight string
	Seeds       []string
}

type TargetSeedKiraConfig struct {
	IpAddress     string
	InterxPort    string
	SekaidRPCPort string
	SekaidP2PPort string
}

type syncInfo struct {
	rpcServers       []string
	trustHeightBlock string
	trustHashBlock   string
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

func GetStandardConfigPack() []config.TomlValue {
	// TODO: should we remove this func and insert default values directly? Need to sync with new network creator
	cfg := config.DefaultRyokaiConfig()

	configs := []config.TomlValue{
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

	listOfSeeds, err := parsePubP2PListResponse(pupP2PListResponse)
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

	body, err := httpexecutor.DoGetHttpQuery(ctx, client, url)
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
	body, err := httpexecutor.DoGetHttpQuery(ctx, client, url)
	if err != nil {
		log.Printf("ERROR: Querying error: %s", err)
		return nil, err
	}

	return body, nil
}

func parsePubP2PListResponse(seedsResponse []byte) ([]string, error) {
	if len(seedsResponse) == 0 {
		log.Printf("WARNING: The list of public seeds is not available")
		return nil, nil
	}

	linesOfPeers := strings.Split(string(seedsResponse), "\n")
	listOfSeeds := make([]string, 0)

	for _, line := range linesOfPeers {
		formattedSeed := fmt.Sprintf("tcp://%s", line)
		log.Printf("DEBUG: Got seed: %s", formattedSeed)
		listOfSeeds = append(listOfSeeds, formattedSeed)
	}

	return listOfSeeds, nil
}

// GetConfigsBasedOnSeed generates a slice of configuration values based on the provided network information
// and joins the seeds, RPC servers, and other relevant parameters into the configuration values.
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
	log.Printf("DEBUG: configValues %+v", configValues)
	// return nil, fmt.Errorf("TestError")
	return configValues, nil
}

func GetJoinerAppConfig(grpcPort uint) []config.TomlValue {
	return []config.TomlValue{
		{Tag: "state-sync", Name: "snapshot-interval", Value: "200"},
		{Tag: "state-sync", Name: "snapshot-keep-recent", Value: "2"},
		{Tag: "", Name: "pruning", Value: "custom"},
		{Tag: "", Name: "pruning-keep-recent", Value: "2"},
		{Tag: "", Name: "pruning-keep-every", Value: "100"},
		{Tag: "", Name: "pruning-interval", Value: "10"},
		{Tag: "grpc", Name: "address", Value: fmt.Sprintf("0.0.0.0:%v", grpcPort)},
	}
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

// getSyncInfo retrieves synchronization information based on a list of RPC servers and a minimum block height.
// It queries each RPC server for block information at the specified height and checks if the retrieved data is consistent.
func getSyncInfo(ctx context.Context, client *http.Client, listOfRPC []string, minHeight string) (*syncInfo, error) {

	resultSyncInfo := &syncInfo{
		rpcServers:       []string{},
		trustHeightBlock: "",
		trustHashBlock:   "",
	}

	// TODO: do it in concurrency so don't have to wait each unsuccessful connection to time out individually
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

	log.Printf(" %+v", resultSyncInfo)
	return resultSyncInfo, nil
}

// getBlockInfo queries block information from a specified RPC server at a given block height using an HTTP GET request.
// It constructs the URL based on the provided RPC server URL and the endpointBlock with the specified minHeight parameter.
// The function then makes an HTTP GET request to retrieve the block information as a ResponseBlock struct.
func getBlockInfo(ctx context.Context, client *http.Client, rpcServer, blockHeight string) (*ResponseBlock, error) {
	endpointBlock := fmt.Sprintf("block?height=%s", blockHeight)
	ctx, cancel := context.WithTimeout(ctx, time.Second*3)
	defer cancel()
	url := fmt.Sprintf("http://%s/%s", rpcServer, endpointBlock)
	body, err := httpexecutor.DoGetHttpQuery(ctx, client, url)
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

// applyNewConfig applies a set of configurations to the 'sekaid' application running in the SekaidManager's container.
func ApplyNewConfig(ctx context.Context, configsToml []config.TomlValue, tomlFilePath string) error {
	configFileContent, err := os.ReadFile(tomlFilePath)
	if err != nil {
		return err
	}
	// return fmt.Errorf("TestError")
	config := string(configFileContent)
	var newConfig string
	for _, update := range configsToml {
		newConfig, err = SetTomlVar(&update, config)
		if err != nil {
			log.Printf("Updating ([%s] %s = %s) error: %s\n", update.Tag, update.Name, update.Value, err)

			// TODO What can we do if updating value is not successful?

			continue
		}

		log.Printf("Value ([%s] %s = %s) updated successfully\n", update.Tag, update.Name, update.Value)

		config = newConfig
	}

	err = os.WriteFile(tomlFilePath, []byte(config), 0777)
	if err != nil {
		return err
	}
	return nil
}

// SetTomlVar updates a specific configuration value in a TOML file represented by the 'config' string.
// The function takes the 'tag', 'name', and 'value' of the configuration to update and
// returns the updated 'config' string. It ensures that the provided 'value' is correctly
// formatted in quotes if necessary and handles the update of configurations within a specific tag or section.
// The 'tag' parameter allows specifying the configuration section where the 'name' should be updated.
// If the 'tag' is empty ("") or not found, the function updates configurations in the [base] section.
func SetTomlVar(config *config.TomlValue, configStr string) (string, error) {
	tag := strings.TrimSpace(config.Tag)
	name := strings.TrimSpace(config.Name)
	value := strings.TrimSpace(config.Value)

	log.Printf("Trying to update the ([%s] %s = %s)", tag, name, value)

	if tag != "" {
		tag = "[" + tag + "]"
	}

	lines := strings.Split(configStr, "\n")

	tagLine, nameLine, nextTagLine := -1, -1, -1

	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if tag == "" && StrStartsWith(trimmedLine, name+" =") {
			log.Printf("DEBUG: Found base config '%s' on line: %d", name, i)
			nameLine = i
			break
		}
		if tagLine == -1 && IsSubStr(line, tag) {
			log.Printf("DEBUG: Found tag config '%s' on line: %d", tag, i)
			tagLine = i
			continue
		}

		if tagLine != -1 && nameLine == -1 && IsSubStr(line, name+" =") {
			log.Printf("DEBUG: Found config '%s' from section '%s' on line: %d", tag, name, i)
			nameLine = i
			continue
		}

		if tagLine != -1 && nameLine != -1 && nextTagLine == -1 && IsSubStr(line, "[") && !IsSubStr(line, tag) {
			log.Printf("DEBUG: Found next section after '%s' on line: %d", tag, i)
			nextTagLine = i
			break
		}
	}

	if nameLine == -1 || (nextTagLine != -1 && nameLine > nextTagLine) {
		// return "", &ConfigurationVariableNotFoundError{
		// 	VariableName: name,
		// 	Tag:          tag,
		// }
		return "", fmt.Errorf("field not fount Name: <%v> Tag: <%v> ", name, tag)
	}

	if IsNullOrWhitespace(value) {
		log.Printf("WARN: Quotes will be added, value '%s' is empty or a seq. of white spaces\n", value)
		value = fmt.Sprintf("\"%s\"", value)
	} else if StrStartsWith(value, "\"") && StrEndsWith(value, "\"") {
		log.Printf("WARN: Nothing to do, quotes already present in '%q'\n", value)
	} else if (!StrStartsWith(value, "[")) || (!StrEndsWith(value, "]")) {
		if IsSubStr(value, " ") {
			log.Printf("WARN: Quotes will be added, value '%s' contains white spaces\n", value)
			value = fmt.Sprintf("\"%s\"", value)
		} else if (!IsBoolean(value)) && (!IsNumber(value)) {
			log.Printf("WARN: Quotes will be added, value '%s' is neither a number nor boolean\n", value)
			value = fmt.Sprintf("\"%s\"", value)
		}
	}

	lines[nameLine] = name + " = " + value
	log.Printf("DEBUG: New line is: %q", lines[nameLine])

	return strings.Join(lines, "\n"), nil
}

// IsNullOrWhitespace checks if the given string is either empty or consists of only whitespace characters.
func IsNullOrWhitespace(input string) bool {
	return len(strings.TrimSpace(input)) == 0
}

// IsBoolean checks if the given string represents a valid boolean value ("true" or "false").
func IsBoolean(input string) bool {
	_, err := strconv.ParseBool(input)
	return err == nil
}

// IsNumber checks if the given string represents a valid integer number.
func IsNumber(input string) bool {
	_, err := strconv.ParseInt(input, 0, 64)
	return err == nil
}

// StrStartsWith checks if the given string 's' starts with the specified prefix.
func StrStartsWith(s, prefix string) bool {
	return strings.HasPrefix(s, prefix)
}

// StrEndsWith checks if the given string 's' ends with the specified suffix.
func StrEndsWith(s, suffix string) bool {
	return strings.HasSuffix(s, suffix)
}

// IsSubStr checks if the specified substring 'substring' exists in the given string 's'.
func IsSubStr(s, substring string) bool {
	return strings.Contains(s, substring)
}
