package command

type (
	Handler func(interface{}) (string, error)

	SekaiInit struct {
		ChainID   string `json:"chain-id"`
		Moniker   string `json:"moniker"`
		Home      string `json:"home"`
		LogFmt    string `json:"log_format"`
		LogLvl    string `json:"log_level"`
		Trace     bool   `json:"trace"`
		Overwrite bool   `json:"overwrite"`
	}

	SekaiVersion struct {
		Home string `json:"home"`
	}

	SekaiAddGenesisAcc struct {
		Address string   `json:"address"`
		Home    string   `json:"home"`
		Keyring string   `json:"keyring-backend"`
		LogFmt  string   `json:"log_format"`
		LogLvl  string   `json:"log_level"`
		Trace   bool     `json:"trace"`
		Coins   []string `json:"coins"`
	}

	SekaiGentxClaim struct {
		Address string `json:"address"`
		Keyring string `json:"keyring-backend"`
		Moniker string `json:"moniker"`
		PubKey  string `json:"pubkey"`
		Home    string `json:"home"`
		LogFmt  string `json:"log_format"`
		LogLvl  string `json:"log_level"`
		Trace   bool   `json:"trace"`
	}

	SekaidStart struct {
		Home string `json:"home"` //+
	}
)

const ExecPath = "/sekaid"

var CommandMapping = map[string]struct {
	ArgsStruct func() interface{}
	Handler    Handler
}{
	"init":                {ArgsStruct: func() interface{} { return &SekaiInit{} }, Handler: SekaiInitCmd},
	"version":             {ArgsStruct: func() interface{} { return &SekaiVersion{} }, Handler: SekaiVersionCmd},
	"add-genesis-account": {ArgsStruct: func() interface{} { return &SekaiAddGenesisAcc{} }, Handler: SekaiAddGenesisAccCmd},
	"gentx-claim":         {ArgsStruct: func() interface{} { return &SekaiGentxClaim{} }, Handler: SekaiGentxClaimCmd},
	// "keys-add":            {ArgsStruct: func() interface{} { return &SekaidKeysAdd{} }, Handler: SekaidKeysAddCmd},
	"start": {ArgsStruct: func() interface{} { return &SekaidStart{} }, Handler: SekaidStartCmd},
}
