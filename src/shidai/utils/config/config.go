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
	KiraConfig struct {
		NetworkName         string        // Name of a blockchain name (chain-ID)
		SekaidHome          string        // Home folder for sekai bin
		InterxHome          string        // Home folder for interx bin
		KeyringBackend      string        // Name of keyring backend
		DockerImageName     string        // Name of a docker image that will be used to create containers for sekai and interx
		DockerImageVersion  string        // Version of a docker image that will be used to create containers for sekai and interx
		DockerNetworkName   string        // The name of docker network that will be create and used for sekaid and interx containers
		SekaiVersion        string        // Version of sekai binary
		InterxVersion       string        // Version of interx binary
		SekaidContainerName string        // Name for sekai container
		InterxContainerName string        // Name for interx container
		VolumeName          string        // The name of a docker's volume that will be SekaidContainerName and InterxContainerName will be using
		VolumeMoutPath      string        // Mount point in docker volume for containers
		MnemonicDir         string        // Destination where mnemonics file will be saved
		RpcPort             string        // Sekaid's rpc port
		GrpcPort            string        // Sekaid's grpc port
		P2PPort             string        // Sekaid's p2p port
		PrometheusPort      string        // Prometheus port
		InterxPort          string        // Interx endpoint port
		Moniker             string        // Moniker
		SekaiDebFileName    string        // File name of sekai deb file
		InterxDebFileName   string        // File name of interx deb file
		SecretsFolder       string        // Path to mnemonics.env and node keys
		TimeBetweenBlocks   time.Duration // Awaiting time between blocks
		KiraConfigFilePath  string        // Path to toml km2 config file //default /home/$USER/.config/kira2/kiraConfig.toml
		ConfigTomlValues    []TomlValue   `toml:"-"` // List of configs for update
		Recover             bool          `toml:"-"` // Switch for recover mode
		// MasterMnamonicSet   *vlg.MasterMnemonicSet `toml:"-"`
		// NOTE Default time of block is ~5 seconds!
		// Check (m *MonitoringService) GetConsensusInfo method
		// from cmd/monitoring/main.go
	}
)
