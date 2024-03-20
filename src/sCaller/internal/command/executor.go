package command

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/go-bip39"
)

func SekaiInitCmd(args interface{}) (string, error) {
	cmdArgs, ok := args.(*SekaiInit)
	re := regexp.MustCompile(`\s+`)

	if !ok {
		return "", fmt.Errorf("invalid arguments for 'init'")
	}

	cmd := exec.Command(ExecPath, "init",
		"--home", cmdArgs.Home,
		"--chain-id", cmdArgs.ChainID,
		fmt.Sprintf("%v", re.ReplaceAllString(cmdArgs.Moniker, "_")),
		"--log_level", cmdArgs.LogLvl,
		"--log_format", cmdArgs.LogFmt,
	)

	if cmdArgs.Overwrite {
		cmd.Args = append(cmd.Args, "--overwrite")
	}

	log.Printf("DEBUG: SekaiInitCmd: cmd args: %v", cmd.Args)
	output, err := cmd.CombinedOutput()
	log.Println(string(output))
	return string(output), err
}

func SekaiVersionCmd(interface{}) (string, error) {
	cmd := exec.Command(ExecPath, "version")
	log.Printf("DEBUG: SekaiVersionCmd: cmd: %v", cmd)
	output, err := cmd.CombinedOutput()

	return string(output), err
}

func SekaidKeysAddCmd(args interface{}) (string, error) {
	log.Printf("DEBUG: SekaidKeysAddCmd: in args: %v", args)

	cmdArgs, ok := args.(*SekaidKeysAdd)
	if !ok {
		return "", fmt.Errorf("invalid arguments for 'keys-add'")
	}
	// var config *cfg.Config
	// cfg := cfg.DefaultConfig()
	// cfg.RootDir = cmdArgs.Home
	// cfg.Key
	// nodeId, valPubKey, err := sekaiKeyGen.InitializeNodeValidatorFilesFromMnemonic(cfg, cmdArgs.Mnemonic)
	// if err != nil {
	// 	return "", fmt.Errorf("error setting up <%v> key: %w", cmdArgs.Address, err)
	// }

	mnemonic := cmdArgs.Mnemonic
	if len(mnemonic) == 0 {
		log.Printf("DEBUG: generating new mnemonic")
		log.Printf("DEBUG: entropy seed")
		entropySeed, err := bip39.NewEntropy(256)
		if err != nil {
			return "", fmt.Errorf("error generating new entropy seed: %w", err)
		}
		log.Printf("DEBUG: entropy seed: %v", string(entropySeed))

		mnemonic, err = bip39.NewMnemonic(entropySeed)
		if err != nil {
			return "", fmt.Errorf("error generating new mnemonic: %w", err)
		}
		log.Printf("DEBUG: mnemonic: %v", mnemonic)

	} else {
		check := bip39.IsMnemonicValid(mnemonic)
		if !check {
			return "", fmt.Errorf("mnemonic is not valid <%v>", mnemonic)
		}
		log.Printf("DEBUG: received mnemonic is valid: %v", mnemonic)
	}
	// var kb keyring.Keyring
	// kb, err := key.NewAccount("myKeyName", "myMnemonic", "", "/path/to/keys", hd.Secp256k1)
	// if err != nil {
	// 	// Handle error
	// }

	registry := types.NewInterfaceRegistry()
	marshaler := codec.NewProtoCodec(registry)
	kb, err := keyring.New(
		"myAppName",         // Keyring name
		keyring.BackendTest, // Backend type
		cmdArgs.Home,        // Keys directory path
		os.Stdin,            // io.Reader for entropy
		marshaler,           // codec.Codec for encoding/decoding
		// Add any additional keyring.Option here if needed
	)
	if err != nil {
		return "", fmt.Errorf("error creating new keyring: %w", err)
	}
	//default values from sekai
	coinType := sdk.GetConfig().GetCoinType()
	var account uint32 = 0
	var index uint32 = 0
	algoStr := string(hd.Secp256k1Type)
	keyringAlgos, _ := kb.SupportedAlgorithms()
	log.Printf("DEBUG: default values for algo string: %v, %v, %v, %v, %v", coinType, account, index, algoStr, keyringAlgos)

	algo, err := keyring.NewSigningAlgoFromString(algoStr, keyringAlgos)
	if err != nil {
		return "", fmt.Errorf("error creating new signing algorithm: %w", err)
	}
	log.Printf("DEBUG: algorithm: %v", algo)

	hdPath := hd.CreateHDPath(coinType, account, index).String()
	log.Printf("DEBUG: hdPath: %v", hdPath)

	k, err := kb.NewAccount(cmdArgs.Address, mnemonic, "", hdPath, algo)
	if err != nil {
		return "", fmt.Errorf("error creating new account: %w", err)
	}
	log.Printf("DEBUG: key: %v", k)
	// cmd := exec.Command(ExecPath, "keys", "add", cmdArgs.Address,
	// 	"--keyring-backend", cmdArgs.Keyring,
	// 	"--home", cmdArgs.Home,
	// 	"--log_format", cmdArgs.LogFmt,
	// 	"--log_level", cmdArgs.LogLvl,
	// )

	// if cmdArgs.Output != "" {
	// 	cmd.Args = append(cmd.Args, "--output", cmdArgs.Output)
	// }
	// if cmdArgs.Recover {
	// 	cmd.Args = append(cmd.Args, "--recover")
	// }
	// if cmdArgs.Trace {
	// 	cmd.Args = append(cmd.Args, "--trace")
	// }

	// log.Printf("DEBUG: SekaidKeysAddCmd: cmd args: %v", cmd.Args)
	// output, err := cmd.CombinedOutput()
	// log.Println(string(output))
	// return string(output), err
	// return fmt.Sprintf("Key added:%s", k), nil
	return "RETURN SECCUSESFULL", nil
}

func SekaiAddGenesisAccCmd(args interface{}) (string, error) {
	cmdArgs, ok := args.(*SekaiAddGenesisAcc)
	if !ok {
		return "", fmt.Errorf("invalid arguments for 'add-genesis-account'")
	}

	cmd := exec.Command(ExecPath, "add-genesis-account", cmdArgs.Address, strings.Join(cmdArgs.Coins, ","), "--home", cmdArgs.Home, "--keyring-backend", cmdArgs.Keyring, "--log_format", cmdArgs.LogFmt, "--log_level", cmdArgs.LogLvl)
	if cmdArgs.Trace {
		cmd.Args = append(cmd.Args, "--trace")
	}

	log.Printf("DEBUG: SekaiAddGenesisAccCmd: cmd args: %v", cmd.Args)
	output, err := cmd.CombinedOutput()
	log.Println(string(output))
	return string(output), err
}

func SekaiGentxClaimCmd(args interface{}) (string, error) {
	cmdArgs, ok := args.(*SekaiGentxClaim)
	if !ok {
		return "", fmt.Errorf("invalid arguments for 'gentx-claim'")
	}
	cmd := exec.Command(
		ExecPath, "gentx-claim", cmdArgs.Address,
		"--keyring-backend", cmdArgs.Keyring,
		"--moniker", fmt.Sprintf("%q", cmdArgs.Moniker),
		"--pubkey", cmdArgs.PubKey,
		"--home", cmdArgs.Home,
		"--log_format", cmdArgs.LogFmt,
		"--log_level", cmdArgs.LogLvl)

	if cmdArgs.Trace {
		cmd.Args = append(cmd.Args, "--trace")
	}
	log.Printf("DEBUG: SekaiGentxClaimCmd: cmd args: %v", cmd.Args)
	output, err := cmd.CombinedOutput()
	log.Println(string(output))

	return string(output), err
}

func SekaidStartCmd(args interface{}) (string, error) {
	cmdArgs, ok := args.(*SekaidStart)
	if !ok {
		return "", fmt.Errorf("invalid arguments for 'start'")
	}

	argv := []string{"sekaid", "start", "--home", cmdArgs.Home}
	env := os.Environ()
	log.Printf("DEBUG: SekaidStartCmd: cmd args: %v", fmt.Sprintln(ExecPath, argv, env))
	err := syscall.Exec(ExecPath, argv, env)

	return "", err
}
