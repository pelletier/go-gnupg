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
	line, e := gpg.CreateKeyPair(1024, "me@foo.com", "myname", "comment", "qweqwe")
	if e != nil {
		t.Fatal(e)
	}
	re := regexp.MustCompile("[A-Z0-9]+")
	if !re.MatchString(line) {
		t.Fatalf("%s does not look like a valid key ID", line)
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
