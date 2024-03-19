package osUtils

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"

	"github.com/google/shlex"
	"github.com/sirupsen/logrus"
)

var errSamePath = errors.New("cannot use same path for source and destination")

// CopyFile copies the contents of a file from a source path to a destination path.
// It checks if the source and destination paths are the same, returning an error if they are.
// Logs the copying action, specifying the source and destination paths for clarity.
// Opens the source file for reading. If it fails to open, returns the encountered error.
// Ensures the source file is closed after its contents have been read, using defer.
// Creates the destination file for writing. If creation fails, returns the encountered error.
// Also ensures the destination file is closed after writing, using defer.
// Performs the actual copying of contents from the source file to the destination file.
// If the copy operation fails, returns the encountered error.
// Logs a success message upon successful copying.
// Returns nil error on successful copy, indicating the operation was successful.
func CopyFile(src, dst string) error {
	if src == dst {
		return errSamePath
	}

	logrus.Printf("Copying from <%s> to <%s>", src, dst)

	srcFile, err := os.Open(src)
	if err != nil {
		return err //nolint:wrapcheck
	}

	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err //nolint:wrapcheck
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err //nolint:wrapcheck
	}

	logrus.Printf("Copying was successful")

	return nil
}

// GetUser retrieves the current system user. It first checks if the "SUDO_USER"
// environment variable is set, indicating that the program is running with sudo.
// If "SUDO_USER" is present, it attempts to look up the user by this name.
// If the lookup is successful, it returns the user information. If "SUDO_USER" is
// not set or the lookup fails, it falls back to returning the current user executing
// the program. This function returns a pointer to a user.User struct and an error,
// which will be non-nil if any lookup operations fail.
func GetUser() (*user.User, error) {
	v, ok := os.LookupEnv("SUDO_USER")
	if ok {
		return user.Lookup(v) //nolint:wrapcheck
	}

	return user.Current() //nolint:wrapcheck
}

// IsDir checks if the given path represents a directory.
// It attempts to retrieve file information using os.Stat.
// If an error occurs (e.g., the path does not exist), it logs the error and returns false.
// Otherwise, it checks the file mode to determine if the path is a directory.
// Returns true if the path is a directory; otherwise, false.
func IsDir(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		logrus.Print(err)

		return false
	}

	return info.IsDir()
}

// FileExist checks if a file or directory exists at the specified path.
// It uses os.Stat to attempt to retrieve the file information.
// If os.Stat returns nil error, the file exists, and the function returns true.
// If the error is of type os.IsNotExist, indicating the file does not exist, it returns false.
// For any other type of error, it also returns false, treating inaccessible files as non-existent.
func FileExist(path string) bool {
	_, err := os.Stat(path)

	switch {
	case err == nil:
		return true
	case os.IsNotExist(err):
		return false
	default:
		return false
	}
}

// Uses net.ParseIP to attempt parsing the input string as an IP address.
// If the input cannot be parsed into a valid IP address (net.ParseIP returns nil),
// logs a message indicating the input is not a valid IP.
// Returns false if the input is not a valid IP address.
// Returns true if the input is successfully parsed as a valid IP address.
func ValidateIP(input string) bool {
	ipCheck := net.ParseIP(input)
	if ipCheck == nil {
		logrus.Printf("<%s> is not a valid ip", input)

		return false
	}

	return true
}

// ValidatePort converts the input string to an integer and checks if it represents a valid port number.
// Uses strconv.Atoi to convert the input string to an integer.
// If conversion fails (e.g., input is not an integer), returns false.
// Checks if the converted integer falls within the valid range for TCP/UDP port numbers (0 to 65535).
// Returns true if the port number is within the valid range; otherwise, returns false.
func ValidatePort(input string) bool {
	port, err := strconv.Atoi(input)
	if err != nil {
		return false
	}

	return !(port < 0 || port > 65535)
}

// RunCommand executes the given command string in the system's shell
// and returns its combined standard output and standard error.
// The command string is split into the command and its arguments using
// shlex.Split for proper handling of spaces and quotes.
// It initializes a new Cmd structure to represent an external command to be executed,
// passing the command and its arguments separately.
// If the command execution fails or if there's an error in splitting the command string,
// it returns an error detailing the issue encountered.
func RunCommand(command string) ([]byte, error) {
	args, err := shlex.Split(command)
	if err != nil {
		return []byte{}, fmt.Errorf("error when spiting cmd to array of args, err: %w", err)
	}

	logrus.Printf("Running: <%s>", command)

	cmd := exec.Command(args[0], args[1:]...) //nolint:gosec

	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("error when executing <%s>, err: %w", command, err)
	}

	return (out), nil
}

// CreateFileWithData creates a new file at the specified filePath and writes the given data to it.
// Attempts to create the file using os.Create. If this fails,
// returns an error indicating the file could not be created.
// Ensures the file is closed after writing is completed, using defer to handle this automatically.
// Writes the provided byte slice data to the file. If writing fails, returns an error indicating the write failure.
// Returns nil if the file is successfully created and the data is written without errors.
func CreateFileWithData(filePath string, data []byte) error {
	logrus.Printf("Creating <%s> file", filePath)

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write data to file: %w", err)
	}

	return nil
}
