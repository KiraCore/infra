package cosmosHelper

import (
	"fmt"
	"log"
	"os"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/go-bip39"
)

func AddKeyToKeyring(keyName, mnemonic, homeFolder, keyringType string) (*keyring.Record, error) {
	if keyName == "" {
		return nil, fmt.Errorf("key name cannot be empty")
	}
	check := bip39.IsMnemonicValid(mnemonic)
	if !check {
		return nil, fmt.Errorf("mnemonic is not valid <%v>", mnemonic)
	}
	log.Printf("DEBUG: received mnemonic is valid: %v", mnemonic)

	if keyringType == "" {
		keyringType = keyring.BackendOS // setting up default value for keyring = "os" check AddKeyringFlags() from sekai
	}

	registry := types.NewInterfaceRegistry()
	marshaler := codec.NewProtoCodec(registry)
	kb, err := keyring.New(
		sdk.KeyringServiceName(), // Keyring name
		keyringType,              // Backend type
		homeFolder,               // Keys directory path
		os.Stdin,                 // io.Reader for entropy
		marshaler,                // codec.Codec for encoding/decoding
	)
	if err != nil {
		return nil, fmt.Errorf("error creating new keyring: %w", err)
	}
	// from cosmosSdk cmd AddKeyCommand() from cosmosSDK/client/keys/add.go
	// default values from cosmosSDK (same for sekai)
	coinType := sdk.GetConfig().GetCoinType()
	var account uint32 = 0
	var index uint32 = 0
	algoStr := string(hd.Secp256k1Type)
	keyringAlgos, _ := kb.SupportedAlgorithms()
	log.Printf("DEBUG: default values for algo string: %v, %v, %v, %v, %v", coinType, account, index, algoStr, keyringAlgos)

	algo, err := keyring.NewSigningAlgoFromString(algoStr, keyringAlgos)
	if err != nil {
		return nil, fmt.Errorf("error creating new signing algorithm: %w", err)
	}

	hdPath := hd.CreateHDPath(coinType, account, index).String()
	log.Printf("DEBUG: hdPath: %v", hdPath)

	k, err := kb.NewAccount(keyName, mnemonic, "", hdPath, algo)
	if err != nil {
		return nil, fmt.Errorf("error creating new account: %w", err)
	}
	k.GetAddress()
	return k, nil
}

// # # Usage:
//
// # Get for example keyRecord from AddKeyToKeyring() func
//
//	k , _ := AddKeyToKeyring(keyName, mnemonic, homeFolder, keyringType)
//
// # Convert keyRecord to address
//
//	address, _ := k.GetAddress()
//
// # Convert hex string to bytes
//
//	addrBytes, _ := sdk.GetFromBech32(address.String(), "cosmos")
//
// # After use this function to retrieve Kira address
//
//	kiraAddress, _ := ConvertBech32AddressToKiraAddress(addrBytes)
func ConvertBech32AddressToKiraAddress(addrBytes []byte) (string, error) {
	bech32Addr, err := sdk.Bech32ifyAddressBytes("kira", addrBytes)
	if err != nil {
		log.Printf("ERROR: converting to Bech32 address: %s\n", err)
		return "", fmt.Errorf("error when converting to Bech32 address: %w", err)
	}
	log.Printf("DEBUG: Kira Address: %v", bech32Addr)
	return bech32Addr, nil
}

func GenerateNewMnemonic() (string, error) {
	entropySeed, err := bip39.NewEntropy(256)
	if err != nil {
		return "", fmt.Errorf("error generating new entropy seed: %w", err)
	}
	mnemonic, err := bip39.NewMnemonic(entropySeed)
	if err != nil {
		return "", fmt.Errorf("error generating new mnemonic: %w", err)
	}
	return mnemonic, nil
}
