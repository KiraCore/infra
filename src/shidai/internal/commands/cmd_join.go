package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	tomlEditor "shidai/utils/TomlEditor"
	"shidai/utils/cosmosHelper"
	httpexecutor "shidai/utils/httpExecutor"
	joinermanager "shidai/utils/joinerManager"
	"shidai/utils/mnemonicController"
	"shidai/utils/osUtils"
	"strconv"
	"time"
)

type JoinCommandHandler struct {
	IPToJoin      string `json:"ip"`         // ip to join
	InterxPort    int    `json:"interxPort"` // 11000
	RpcPortToJoin int    `json:"rpcPort"`    // 26657
	P2PPortToJoin int    `json:"p2pPort"`    // 26656
	Mnemonic      string `json:"mnemonic"`   //
}

func init() {
	RegisterCommand("join", &JoinCommandHandler{})
}

func (j *JoinCommandHandler) HandleCommand(args map[string]interface{}) error {

	//relative path to interx and sekai volumes
	const (
		SekaidVolume = "/sekai"
		InterxVolume = "/interx"

		InterxdHome = InterxVolume + "/interxd"
		SekaidHome  = SekaidVolume + "/sekaid"
	)

	jsonData, err := json.Marshal(args)
	if err != nil {
		return fmt.Errorf("error marshalling map to JSON: %w", err)
	}
	// var handler JoinCommandHandler
	err = json.Unmarshal(jsonData, j)
	if err != nil {
		return fmt.Errorf("error unmarshalling JSON to struct: %w", err)
	}
	err = j.ValidateJoinCommand()
	if err != nil {
		return fmt.Errorf("error validating command arguments: %w", err)
	}
	err = j.InitJoinerNode(SekaidHome, InterxdHome)
	if err != nil {
		return fmt.Errorf("error when joining: %w", err)
	}
	return nil
}

// func cleanup and create folder for shidai
func (j *JoinCommandHandler) CleanUpSekaidAndInterxHome(sekaidHome, interxdHome string) error {
	// TODO: shutdown sekaid and interx docker container
	check := osUtils.FileExist(sekaidHome)
	if check {
		err := os.RemoveAll(sekaidHome)
		if err != nil {
			return err
		}
	}

	check = osUtils.FileExist(interxdHome)
	if check {
		err := os.RemoveAll(interxdHome)
		if err != nil {
			return err
		}
	}

	return nil
}

func (j *JoinCommandHandler) ValidateJoinCommand() error {
	check := osUtils.ValidateIP(j.IPToJoin)
	if !check {
		return fmt.Errorf("<%v> in not a valid ip", j.IPToJoin)
	}
	check = osUtils.ValidatePort(strconv.Itoa(j.P2PPortToJoin))
	if !check {
		return fmt.Errorf("<%v> in not a valid port", j.P2PPortToJoin)
	}

	check = osUtils.ValidatePort(strconv.Itoa(j.RpcPortToJoin))
	if !check {
		return fmt.Errorf("<%v> in not a valid port", j.RpcPortToJoin)
	}

	check = osUtils.ValidatePort(strconv.Itoa(j.InterxPort))
	if !check {
		return fmt.Errorf("<%v> in not a valid port", j.InterxPort)
	}

	return nil
}

func (j *JoinCommandHandler) InitJoinerNode(sekaidHome, interxdHome string) error {
	err := j.CleanUpSekaidAndInterxHome(sekaidHome, interxdHome)
	if err != nil {
		return fmt.Errorf("unable to clean up sekai and interx homes: %w", err)
	}
	sekaidContainerName := "sekin-sekaid_rpc-1"

	// run version to generate config.toml, app.toml,client.toml files inside sekaid home folder
	// TODO: generate base config files with cosmosSDK
	cmd := httpexecutor.CommandRequest{
		Command: "version",
		Args: httpexecutor.SekaidKeysAdd{

			Home: sekaidHome,
		},
	}
	out, err := httpexecutor.ExecutePostCommand(sekaidContainerName, "8080", cmd)
	if err != nil {
		return fmt.Errorf("unable execute <%v> request, error: %w", cmd, err)
	}

	log.Println(string(out))

	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Minute*5)

	defer cancelFunc()
	genesis, err := joinermanager.GetVerifiedGenesisFile(ctx, j.IPToJoin, j.RpcPortToJoin, j.InterxPort)
	if err != nil {
		return fmt.Errorf("unable to receive genesis file: %w", err)
	}
	log.Printf("%v\n", string(genesis))
	err = os.WriteFile(fmt.Sprintf("%v/config/genesis.json", sekaidHome), genesis, 0644)
	if err != nil {
		return fmt.Errorf("cant write genesis.json file: %w", err)
	}

	// TODO: should we generate mnemonic or force user to set Mnemonic
	// Generate masterMnemonic if current mnemonic is empty
	var masterMnemonic string
	if j.Mnemonic == "" {
		// TODO: use cosmosSDK generate function (it more simpler and straightforward (kira1 uses this))
		bip39m, err := mnemonicController.GenerateMnemonic()
		if err != nil {
			return fmt.Errorf("unable to generate masterMnemonic: %w", err)
		}
		masterMnemonic = bip39m.String()
	} else {
		err := mnemonicController.ValidateMnemonic(j.Mnemonic)
		if err != nil {

			return fmt.Errorf("unable to validate mnemonic: %w", err)
		}
		masterMnemonic = j.Mnemonic
	}

	//Generate master mnemonic set
	secretsFolder := "/sekai/.secrets"
	err = os.MkdirAll(secretsFolder, 0755)
	if err != nil {
		return fmt.Errorf("unable to create secrets folder: %w", err)
	}
	masterMnemonicsSet, err := mnemonicController.GenerateMnemonicsFromMaster(masterMnemonic, secretsFolder)
	if err != nil {
		return fmt.Errorf("unable to generate master mnemonic set: %w", err)
	}

	err = mnemonicController.SetSekaidKeys(sekaidHome, secretsFolder)
	if err != nil {
		return fmt.Errorf("unable to set sekaid keys: %w", err)
	}
	err = mnemonicController.SetEmptyValidatorState(sekaidHome)
	if err != nil {
		return fmt.Errorf("unable to set empty validator state : %w", err)
	}

	_, err = cosmosHelper.AddKeyToKeyring("validator", string(masterMnemonicsSet.ValidatorAddrMnemonic), sekaidHome, "test")
	if err != nil {
		return fmt.Errorf("unable to add validator key to keyring: %w", err)
	}
	tc := tomlEditor.TargetSeedKiraConfig{
		IpAddress:     j.IPToJoin,
		InterxPort:    strconv.Itoa(j.InterxPort),
		SekaidRPCPort: strconv.Itoa(j.RpcPortToJoin),
		SekaidP2PPort: strconv.Itoa(j.P2PPortToJoin),
	}
	err = j.ApplyJoinerTomlSettings(sekaidHome, &tc)
	if err != nil {
		return fmt.Errorf("unable retrieve join information from <%s>, error: %w", "IP OF THE NODE", err)
	}
	cmd = httpexecutor.CommandRequest{
		Command: "start",
		Args: httpexecutor.SekaidStart{
			Home: sekaidHome,
		},
	}

	// TODO: rework start in iCaller, it returns error "EOL" when successfully started
	out, err = httpexecutor.ExecutePostCommand(sekaidContainerName, "8080", cmd)
	if err != nil {
		return fmt.Errorf("unable execute <%v> request, error: %w", cmd, err)
	}
	log.Println(string(out))

	// TODO: add interx init (can be turned off with http request)

	return nil
}

// TODO: move this func to another place
func (j *JoinCommandHandler) ApplyJoinerTomlSettings(sekaidHome string, tc *tomlEditor.TargetSeedKiraConfig) error {
	ctx := context.Background()

	client := &http.Client{}
	info, err := tomlEditor.RetrieveNetworkInformation(ctx, client, tc)
	if err != nil {
		return err
	}
	log.Printf("DEBUG: info: %+v", info)

	standardTomlValues := tomlEditor.GetStandardConfigPack()
	// Get config for config.toml
	configFromSeed, err := tomlEditor.GetConfigsBasedOnSeed(ctx, client, info, tc)
	if err != nil {
		return err
	}
	updates := append(standardTomlValues, configFromSeed...)
	// apply new config for toml.config
	err = tomlEditor.ApplyNewConfig(ctx, updates, fmt.Sprintf("%v/config/config.toml", sekaidHome))
	if err != nil {
		return err
	}

	err = tomlEditor.ApplyNewConfig(ctx, tomlEditor.GetJoinerAppConfig(9090), fmt.Sprintf("%v/config/app.toml", sekaidHome))
	if err != nil {
		return err
	}

	return nil
}
