package commands

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"shidai/utils/mnemonicController"
	"shidai/utils/osUtils"
	"strconv"
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
	// ctx, cancelFunc := context.WithTimeout(context.Background(), time.Minute*5)

	// defer cancelFunc()
	// genesis, err := joinermanager.GetVerifiedGenesisFile(ctx, j.IPToJoin, j.RpcPortToJoin, j.InterxPort)
	// if err != nil {
	// 	return fmt.Errorf("unable to receive genesis file: %w", err)
	// }
	// log.Printf("%v\n", string(genesis))

	// TODO: should we generate mnemonic or force user to set Mnemonic
	// Generate masterMnemonic if current mnemonic is empty
	var masterMnemonic string
	if j.Mnemonic == "" {
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
	MasterMnemonicsSet, err := mnemonicController.GenerateMnemonicsFromMaster(masterMnemonic, secretsFolder)
	if err != nil {
		return fmt.Errorf("unable to generate master mnemonic set: %w", err)
	}

	err = mnemonicController.SetSekaidKeys(sekaidHome, secretsFolder)
	if err != nil {
		return fmt.Errorf("unable to set sekaid keys: %w", err)
	}
	err = mnemonicController.SetEmptyValidatorState(sekaidHome)
	log.Printf("ValidatorAddrMnemonic: %+v\n", string(MasterMnemonicsSet.ValidatorAddrMnemonic))
	if err != nil {
		return fmt.Errorf("unable to set empty validator state : %w", err)
	}
	//Writing masterMnemonic to sekai volume
	// Generate secrets folder in docker container

	// log.Printf("Handler: %+v\n", j)
	return nil
}
