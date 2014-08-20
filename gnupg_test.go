package gnupg

import (
	"testing"
)

func TestGnupgInit(t *testing.T) {
	gpg, err := InitGnupg()
	if err != nil {
		t.Error("Gnupg initialization failed:", err)
		return
	}
	if gpg.Binary == "" {
		t.Error("gpg's path is empty")
	}
}

func TestGnupgCreateKeys(t *testing.T) {
	gpg, _ := InitGnupg()
	line, e := gpg.CreateKeys("me@foo.com", "myname", "comment", "qweqwe")
	if e != nil {
		t.Error(e)
	} else {
		t.Log(line)
	}
}
