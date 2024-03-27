package config

import "time"

type (
	// TomlValue represents a configuration value to be updated in the '*.toml' file of the 'sekaid' application.
	TomlValue struct {
		Tag   string
		Name  string
		Value string
	}

	// JsonValue represents a configuration value to be updated in the '*.json' file of the 'interx' application
	JsonValue struct {
		Key   string // Dot-separated keys by nesting
		Value any
	}

	// KiraConfig is a configuration for sekaid or interx manager.
	RyokaiConfig struct {
		NetworkName       string        // Name of a blockchain name (chain-ID)
		SekaidHome        string        // Home folder for sekai bin
		InterxHome        string        // Home folder for interx bin
		KeyringBackend    string        // Name of keyring backend
		VolumeName        string        // The name of a docker's volume that will be SekaidContainerName and InterxContainerName will be using
		VolumeMoutPath    string        // Mount point in docker volume for containers
		MnemonicDir       string        // Destination where mnemonics file will be saved
		RpcPort           string        // Sekaid's rpc port
		GrpcPort          string        // Sekaid's grpc port
		P2PPort           string        // Sekaid's p2p port
		PrometheusPort    string        // Prometheus port
		InterxPort        string        // Interx endpoint port
		Moniker           string        // Moniker
		SecretsFolder     string        // Path to mnemonics.env and node keys
		TimeBetweenBlocks time.Duration // Awaiting time between blocks
		ConfigTomlValues  []TomlValue   `toml:"-"` // List of configs for update
		// MasterMnamonicSet   *vlg.MasterMnemonicSet `toml:"-"`
		// NOTE Default time of block is ~5 seconds!
		// Check (m *MonitoringService) GetConsensusInfo method
		// from cmd/monitoring/main.go
	}
)

func DefaultRyokaiConfig() *RyokaiConfig {
	return &RyokaiConfig{
		NetworkName:       "shidaiNet-1",
		SekaidHome:        "/sekai/sekaid",
		InterxHome:        "/interx/interxd",
		KeyringBackend:    "test",
		VolumeName:        "kira_volume",
		VolumeMoutPath:    "/sekai",
		MnemonicDir:       "~/mnemonics",
		RpcPort:           "26657",
		P2PPort:           "26656",
		GrpcPort:          "9090",
		PrometheusPort:    "26660",
		InterxPort:        "11000",
		Moniker:           "VALIDATOR",
		TimeBetweenBlocks: time.Second * 10,
	}
}
