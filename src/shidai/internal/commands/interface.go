package commands

type Command interface {
	Name() string
	Execute() error
}
