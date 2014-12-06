package gnupg

import (
	"regexp"
	"testing"
)

var binpath string = "./gpg"

func TestGnupgInit(t *testing.T) {
	gpg, err := InitGnupg()
	if err != nil {
		t.Fatal("Gnupg initialization failed:", err)
	}
	t.Logf("Testing using %s\n", gpg.Binary)
	if gpg.Binary == "" {
		t.Fatal("gpg's path is empty")
	}
}

func TestGnupgCreateKeys(t *testing.T) {
	gpg, _ := InitGnupg()
	line, e := gpg.CreateKeyPair(1024, "me@foo.com", "myname", "comment", "qweqwe")
	if e != nil {
		t.Fatal(e)
	}
	re := regexp.MustCompile("[A-Z0-9]+")
	if !re.MatchString(line) {
		t.Fatalf("%s does not look like a valid key ID", line)
	}
}


func TestGnupgChangePasskey(t *testing.T) {
	gpg, _ := InitGnupg()
	line, e := gpg.CreateKeyPair(1024, "me2@foo.com", "myname", "comment", "qweqwe")
	if e != nil {
		t.Fatal(e)
	}
	re := regexp.MustCompile("[A-Z0-9]+")
	if !re.MatchString(line) {
		t.Fatalf("%s does not look like a valid key ID", line)
	}
	e = gpg.ChangePasskey(line, "qweqwe", "lol")
	if e != nil {
		t.Fatal(e)
	}
	e = gpg.ChangePasskey(line, "qweqwe", "lol")
	if e == nil {
		t.Fatal("Second passkey change should not be successful")
	}
}

func TestGnupgExportPublicKey(t *testing.T) {
	gpg, _ := InitGnupg()
	keyid, _ := gpg.CreateKeyPair(1024, "me@foo.com", "myname", "comment", "qweqwe")
	pkey, err := gpg.ExportPublicKey(keyid)
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?sm)^-----BEGIN PGP PUBLIC KEY BLOCK-----.*-----END PGP PUBLIC KEY BLOCK-----$`)
	if !re.MatchString(pkey) {
		t.Fatalf("%s\ndoes not look like a valid armored public key", pkey)
	}
}

func TestGnupgExportPrivateKey(t *testing.T) {
	gpg, _ := InitGnupg()
	keyid, _ := gpg.CreateKeyPair(1024, "me@foo.com", "myname", "comment", "qweqwe")
	pkey, err := gpg.ExportPrivateKey(keyid)
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?sm)^-----BEGIN PGP PRIVATE KEY BLOCK-----.*-----END PGP PRIVATE KEY BLOCK-----$`)
	if !re.MatchString(pkey) {
		t.Fatalf("%s\ndoes not look like a valid armored private key", pkey)
	}
}

func TestGnupgDeletePrivateKey(t *testing.T) {
	gpg, _ := InitGnupg()
	keyid, _ := gpg.CreateKeyPair(1024, "me@foo.com", "myname", "comment", "qweqwe")
	err := gpg.DeletePrivateKey(keyid)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGnupgDeletePublicKey(t *testing.T) {
	gpg, _ := InitGnupg()
	keyid, _ := gpg.CreateKeyPair(1024, "me@foo.com", "myname", "comment", "qweqwe")
	gpg.DeletePrivateKey(keyid)
	err := gpg.DeletePublicKey(keyid)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGnupgDeleteKeys(t *testing.T) {
	gpg, _ := InitGnupg()
	keyid, _ := gpg.CreateKeyPair(1024, "me@foo.com", "myname", "comment", "qweqwe")
	err := gpg.DeleteKeys(keyid)
	if err != nil {
		t.Fatal(err)
	}
}
