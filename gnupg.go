// GnuPG wrapper
//
// Simple wrapper around the gpg binary.

package gnupg

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Wrapper object for executing commands agains the gpg binary.
type Gnupg struct {
	Binary  string // Path to the gpg binary
	Homedir string // Path of gpg's homedir (where to store keys)
}

// Element of GPG's status output (for parsing command's results).
type OutputChunk struct {
	Key  string // Output line's key
	Text string // Text attached to the line
}

// Builds a Gnupg object and initializes with sane defaults.
func InitGnupg() (*Gnupg, error) {
	gpg := new(Gnupg)
	path, err := exec.LookPath("gpg")
	if err != nil {
		return nil, errors.New("gpg binary not found")
	}
	gpg.Binary = path
	gpg.Homedir = "~/.gnupg" // there may be a smarter way to initialize that

	return gpg, nil
}

// Execute the gpg binary given some args and optionnaly a string used as stdin.
// Returns the stderr of the execution in form of OutputChunks and the stdout as a string.
func (gpg *Gnupg) ExecCommand(commands []string, input string) ([]OutputChunk, string, error) {
	args := append([]string{
		"--status-fd", "2",
		"--no-tty",
		"--homedir", gpg.Homedir,
	}, commands...)
	cmd := exec.Command(gpg.Binary, args...)

	if len(input) > 0 {
		cmd.Stdin = strings.NewReader(input)
	}

	var stderr, stdout bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout
	err := cmd.Run()

	if err != nil {
		return nil, "", errors.New(fmt.Sprint("gpg failed to run: ", err))
	}

	// XXX Highly not optimised
	allOutput := string(stderr.Bytes())
	lines := strings.Split(allOutput, "\n")

	var chunks = []OutputChunk{}
	for _, line := range lines {
		toks := strings.SplitN(line, " ", 3)
		if toks[0] != "[GNUPG:]" {
			continue
		}
		chunk := OutputChunk{toks[1], ""}
		if len(toks) == 3 {
			chunk.Text = toks[2]
		}
		chunks = append(chunks, chunk)
	}

	return chunks, string(stdout.Bytes()), nil
}

// Creates a pair of RSA public and private keys, protected by a passkey.
// Returns the fingerprint of the newly created key.
func (gpg *Gnupg) CreateKeyPair(length int, email, name, comment, passkey string) (string, error) {
	if length != 1024 && length != 2048 {
		return "", errors.New("Key length has to be 1024 or 2048")
	}
	params := map[string]string{
		"Key-Length":   string(length),
		"Name-Real":    name,
		"Name-Comment": comment,
		"Name-Email":   email,
		"Expire-Date":  "0",
		"Passphrase":   passkey,
	}

	var lines []string
	// Special case for Key-Type, *has* to be the very first line
	lines = append(lines, "Key-Type: RSA")
	for key, value := range params {
		line := fmt.Sprintf("%s: %s", key, value)
		lines = append(lines, line)
	}
	lines = append(lines, "%commit", "")
	input := strings.Join(lines, "\n")

	chunks, _, err := gpg.ExecCommand([]string{"--gen-key", "--batch"}, input)
	if err != nil {
		return "", err
	}

	fingerprint := ""
	for _, chunk := range chunks {
		if chunk.Key == "KEY_CREATED" {
			toks := strings.Split(chunk.Text, " ")
			fingerprint = toks[1]
			break
		}
	}

	return fingerprint, nil
}

// Returns the armored, ascii representation of the given public key.
func (gpg *Gnupg) ExportPublicKey(keyid string) (string, error) {
	_, output, err := gpg.ExecCommand([]string{"--export", "-a", keyid}, "")
	if err != nil {
		return "", err
	}
	return output, nil
}

// Returns the armored, ascii representation of the given private key.
func (gpg *Gnupg) ExportPrivateKey(keyid string) (string, error) {
	_, output, err := gpg.ExecCommand([]string{"--export-secret-key", "-a", keyid}, "")
	if err != nil {
		return "", err
	}
	return output, nil
}

// Delete a private key from the keyring.
func (gpg *Gnupg) DeletePrivateKey(keyids ...string) error {
	args := append([]string{"--batch", "--delete-secret-keys"}, keyids...)
	_, _, err := gpg.ExecCommand(args, "")
	return err
}

// Delete a public key from the keyring.
func (gpg *Gnupg) DeletePublicKey(keyids ...string) error {
	args := append([]string{"--batch", "--delete-keys"}, keyids...)
	_, _, err := gpg.ExecCommand(args, "")
	return err
}

// Delete both the private and public key from the keyring.
func (gpg *Gnupg) DeleteKeys(keyids ...string) error {
	err := gpg.DeletePrivateKey(keyids...)
	if err != nil {
		return err
	}
	return gpg.DeletePublicKey(keyids...)
}
