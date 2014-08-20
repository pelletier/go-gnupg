package gnupg

import (
	"regexp"
	"testing"
)

func TestGnupgInit(t *testing.T) {
	gpg, err := InitGnupg()
	if err != nil {
		t.Fatal("Gnupg initialization failed:", err)
	}
	if gpg.Binary == "" {
		t.Fatal("gpg's path is empty")
	}
}

func TestGnupgCreateKeys(t *testing.T) {
	gpg, _ := InitGnupg()
	line, e := gpg.CreateKeys("me@foo.com", "myname", "comment", "qweqwe")
	if e != nil {
		t.Fatal(e)
	}
	re := regexp.MustCompile("[A-Z0-9]+")
	if !re.MatchString(line) {
		t.Fatalf("%s does not look like a valid key ID", line)
	}
}
