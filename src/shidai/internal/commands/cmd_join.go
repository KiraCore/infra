package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"

	"shidai/utils/osUtils"
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
		InterxdHome = "/interx/interxd"
		SekaidHome  = "/sekai/sekaid"
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

	// ctx, cancelFunc := context.WithTimeout(context.Background(), time.Minute*5)

	// defer cancelFunc()
	// genesis, err := joinermanager.GetVerifiedGenesisFile(ctx, j.IPToJoin, j.RpcPortToJoin, j.InterxPort)
	// if err != nil {
	// 	return fmt.Errorf("unable to receive genesis file: %w", err)
	// }
	// log.Printf("%v\n", string(genesis))
	j.CleanUpSekaidAndInterxHome(SekaidHome, InterxdHome)
	log.Printf("Handler: %+v", j)

	shidaiHome, err := os.MkdirTemp("", "")
	if err != nil {
		return fmt.Errorf("error creating shidai's home: %w", err)
	}
	log.Printf("shidai's home: %v", shidaiHome)
	return nil
}

// func cleanup and create folder for shidai
func (j *JoinCommandHandler) CleanUpSekaidAndInterxHome(sekaidHome, interxHome string) {
	// TODO: shutdown sekaid and interx docker container
	os.Remove(interxHome)
	os.Remove(sekaidHome)

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

func (j *JoinCommandHandler) InitJoinerSekai(ctx context.Context) {

}
