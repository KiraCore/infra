package executors

import (
	"log/slog"

	"shidai/internal/commands"
)

type InitExecutor struct {
	commands []commands.Command
}

func NewInitExecutor(args map[string]interface{}) *InitExecutor {
	return &InitExecutor{
		commands: []commands.Command{
			// TODO add connection between `args` to passed the map of args
			commands.NewCommandRunner("init", map[string]interface{}{
				"chain-id":   "testnet-1",
				"moniker":    "KIRA TEST LOCAL VALIDATOR NODE",
				"home":       "/sekai",
				"log_format": "",
				"log_level":  "",
				"trace":      false,
				"overwrite":  true,
			}),
			// sekaid init \
			//     --chain-id=testnet-1 \
			//     --moniker="KIRA TEST LOCAL VALIDATOR NODE" \
			//     --home=/sekai \
			//     --log_format="" \
			//     --log_level="" \
			//     --overwrite
			commands.NewCommandRunner("keys-add", map[string]interface{}{
				"address":         "genesis",
				"keyring-backend": "test",
				"home":            "/sekai",
			}),
			commands.NewCommandRunner("add-genesis-account", map[string]interface{}{
				"address":         "genesis",
				"coins":           []string{"300000000000000ukex"},
				"keyring-backend": "test",
				"home":            "/sekai",
				"log_format":      "",
				"log_level":       "",
				"trace":           false,
			}),
			commands.NewCommandRunner("gentx-claim", map[string]interface{}{
				"address":         "genesis",
				"keyring-backend": "test",
				"moniker":         "GENESIS VALIDATOR",
				"home":            "/sekai",
			}),
			commands.NewCommandRunner("start", map[string]interface{}{
				"home": "/sekai",
			}),
		},
	}
}

func (e *InitExecutor) Execute( /* config Config */ ) error {
	// Implementation of `shidai init ...`
	// Actually there is not CLI commands.
	// It's just a handler for initialization

	// TODO temporary printing logs
	slog.Info("Executing", "command", "init")

	for index, command := range e.commands {
		slog.Info("Running command", "index", index, "command", command.Name())

		err := command.Execute( /* config Config */ )
		if err != nil {
			slog.Error("Got an error while executing", "error", err)
			return err
		}
	}

	return nil
}
