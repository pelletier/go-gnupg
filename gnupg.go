package gnupg

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os/exec"
	"strings"
)

type Gnupg struct {
	Binary string
}

func InitGnupg() (*Gnupg, error) {
	gpg := new(Gnupg)
	path, err := exec.LookPath("gpg")
	if err != nil {
		return nil, errors.New("gpg binary not found")
	}
	gpg.Binary = path
	return gpg, nil
}

func (gpg *Gnupg) execCommand(commands []string, input string) (string, error) {
	cmd := exec.Command(gpg.Binary, commands...)
	stdout, err := cmd.StdoutPipe()

	c := make(chan string)
	go func() {
		b, _ := ioutil.ReadAll(stdout)
		c <- string(b)
	}()

	if err != nil {
		return "", errors.New(fmt.Sprint("could not grab stdout pipe", err))
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", errors.New(fmt.Sprint("could not grab stdin pipe", err))
	}
	err = cmd.Start()
	if err != nil {
		return "", errors.New(fmt.Sprint("could not start gpg program", err))
	}
	if len(input) > 0 {
		fmt.Println("writing")
		i, err := io.WriteString(stdin, input)
		if err != nil {
			return "", errors.New(fmt.Sprint("could not write to stdin", err))
		}
		if i != len(input) {
			return "", errors.New(fmt.Sprintf("wrote only %d out of %d bytes on stdin", i, len(input)))
		}
	}

	se := <-c

	cmd.Wait()

	if err != nil {
		return "", errors.New(fmt.Sprint("could not retrieve gpg's output: ", err))
	}
	return se, nil
}

func (gpg *Gnupg) CreateKeys(email, name, comment, passkey string) (string, error) {
	params := map[string]string{
		"Key-Type":     "RSA",
		"Key-Length":   "1024",
		"Name-Real":    name,
		"Name-Comment": comment,
		"Name-Email":   email,
		"Expire-Date":  "0",
		"Passphrase":   passkey,
	}
	var lines []string
	for key, value := range params {
		line := fmt.Sprintf("%s: %s", key, value)
		lines = append(lines, line)
	}
	lines = append(lines, "%commit", "")
	input := strings.Join(lines, "\n")
	return gpg.execCommand([]string{"--gen-key", "--batch"}, input)
}
