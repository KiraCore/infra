package commands

type CommandRunner struct {
	commandName string
	Args        map[string]interface{}
}

func NewCommandRunner(cmd string, args map[string]interface{}) *CommandRunner {
	return &CommandRunner{
		Args:        args,
		commandName: cmd,
	}
}

func (c *CommandRunner) Execute() error {
	return postCommand(c.commandName, c.Args)
}

func (c *CommandRunner) Name() string {
	return c.commandName
}
