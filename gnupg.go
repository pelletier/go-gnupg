package gnupg

import (
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

type Gnupg struct {
	Binary  string
	Homedir string
}

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

func (gpg *Gnupg) execCommand(commands []string, input string) (string, error) {
	args := append([]string{"--homedir", gpg.Homedir}, commands...)
	cmd := exec.Command(gpg.Binary, args...)

	if len(input) > 0 {
		cmd.Stdin = strings.NewReader(input)
	}

	stdout, err := cmd.CombinedOutput()

	if err != nil {
		return "", errors.New(fmt.Sprint("gpg failed to run: ", err))
	}
	return string(stdout), nil

}

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
	output, err := gpg.execCommand([]string{"--gen-key", "--batch"}, input)
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile("key ([A-Z0-9]+) marked as ultimately trusted")
	matches := re.FindStringSubmatch(output)
	if len(matches) != 2 {
		return "", errors.New(fmt.Sprint("invalid gpg --gen-key output: ", output))
	}
	return matches[1], nil
}

func (gpg *Gnupg) ExportPublicKey(keyid string) (string, error) {
	output, err := gpg.execCommand([]string{"--export", "-a", keyid}, "")
	if err != nil {
		return "", err
	}
	return output, nil
}

func (gpg *Gnupg) ExportPrivateKey(keyid string) (string, error) {
	output, err := gpg.execCommand([]string{"--export-secret-key", "-a", keyid}, "")
	if err != nil {
		return "", err
	}
	return output, nil
}
