package mnemonicController

import (
	"fmt"
	"log"
	"os"
	"shidai/utils/osUtils"

	vlg "github.com/PeepoFrog/validator-key-gen/MnemonicsGenerator"
	cosmosBIP39 "github.com/cosmos/go-bip39"

	kiraMnemonicGen "github.com/kiracore/tools/bip39gen/cmd"
	"github.com/kiracore/tools/bip39gen/pkg/bip39"
)

func GenerateMnemonicsFromMaster(masterMnemonic, pathForKeys string) (*vlg.MasterMnemonicSet, error) {
	// log.Debugf("GenerateMnemonicFromMaster: masterMnemonic:\n%s", masterMnemonic)
	defaultPrefix := "kira"
	defaultPath := "44'/118'/0'/0/0"

	mnemonicSet, err := vlg.MasterKeysGen([]byte(masterMnemonic), defaultPrefix, defaultPath, pathForKeys)
	if err != nil {
		return &vlg.MasterMnemonicSet{}, err
	}
	// str := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n", mnemonicSet.SignerAddrMnemonic, mnemonicSet.ValidatorNodeMnemonic, mnemonicSet.ValidatorNodeId, mnemonicSet.ValidatorAddrMnemonic, mnemonicSet.ValidatorValMnemonic)
	// log.Infof("Master mnemonic:\n%s", str)
	return &mnemonicSet, nil
}

// func MnemonicReader() (masterMnemonic string) {
// 	// log.Infoln("ENTER YOUR MASTER MNEMONIC:")

// 	reader := bufio.NewReader(os.Stdin)
// 	//nolint:forbidigo // reading user input
// 	fmt.Println("Enter mnemonic: ")

// 	text, err := reader.ReadString('\n')
// 	if err != nil {
// 		// log.Errorf("An error occurred: %s", err)
// 		return
// 	}
// 	mnemonicBytes := []byte(text)
// 	mnemonicBytes = mnemonicBytes[0 : len(mnemonicBytes)-1]
// 	masterMnemonic = string(mnemonicBytes)
// 	return masterMnemonic
// }

// GenerateMnemonic generates random bip 24 word mnemonic
func GenerateMnemonic() (masterMnemonic bip39.Mnemonic, err error) {
	log.Println("generating new mnemonic")
	masterMnemonic = kiraMnemonicGen.NewMnemonic()
	masterMnemonic.SetRandomEntropy(24)
	masterMnemonic.Generate()

	return masterMnemonic, nil
}

func ValidateMnemonic(mnemonic string) error {
	check := cosmosBIP39.IsMnemonicValid(mnemonic)
	if !check {
		return fmt.Errorf("mnemonic <%v> is not valid", mnemonic)
	}
	return nil
}

func SetSekaidKeys(sekaidHome, secretsFolder string) error {
	// TODO path set as variables or constants
	sekaidConfigFolder := sekaidHome + "/config"
	fmt.Println(sekaidConfigFolder)

	//creating sekaid home
	err := os.Mkdir(sekaidHome, 0755)
	if err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("unable to create <%s> folder, err: %w", sekaidHome, err)
		}
	}
	//creating sekaid's config folder
	err = os.Mkdir(sekaidConfigFolder, 0755)
	if err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("unable to create <%s> folder, err: %w", sekaidConfigFolder, err)
		}
	}

	err = osUtils.CopyFile(secretsFolder+"/priv_validator_key.json", sekaidConfigFolder+"/priv_validator_key.json")
	if err != nil {
		return fmt.Errorf("unable to copy <priv_validator_key.json> to <%v>, err: %w", sekaidConfigFolder, err)
	}

	err = osUtils.CopyFile(secretsFolder+"/validator_node_key.json", sekaidConfigFolder+"/node_key.json")
	if err != nil {
		return fmt.Errorf("unable to copy <validator_node_key.json> to <%v>+</node_key.json>, err: %w", sekaidConfigFolder, err)
	}
	return nil
}

// sets empty state of validator into $sekaidHome/data/priv_validator_state.json
func SetEmptyValidatorState(sekaidHome string) error {
	emptyState := `
	{
		"height": "0",
		"round": 0,
		"step": 0
	}`
	sekaidDataFolder := sekaidHome + "/data"
	err := os.Mkdir(sekaidDataFolder, 0755)
	if err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("unable to create <%s> folder, err: %w", sekaidDataFolder, err)
		}
	}
	osUtils.CreateFileWithData(sekaidDataFolder+"/priv_validator_state.json", []byte(emptyState))
	fmt.Println(emptyState, sekaidDataFolder)
	return nil
}
