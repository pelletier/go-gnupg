# go-gnupg

A simple wrapper around the [GnuPG](https://www.gnupg.org/) binary.

[![Build Status](https://img.shields.io/travis/pelletier/go-gnupg.svg?style=flat-square)](https://travis-ci.org/pelletier/go-gnupg)
[![Documentation](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](http://godoc.org/github.com/pelletier/go-gnupg)
[![License](https://img.shields.io/badge/license-MIT-lightgrey.svg?style=flat-square)](http://en.wikipedia.org/wiki/MIT_License)

## Import

    import "github.com/pelletier/go-gnupg"

## Usage

```go
import (
    "fmt"
    "github.com/pelletier/go-gnupg"
)

gpg, _ := Init.Gnupg()
keyid := gpg.CreateKeyPair(2048, "pelletier.thomas@gmail.com", "My Keys", "A set of keys", "mypassphrase")
pubkey := gpg.ExportPublicKey(keyid)
privkey := gpg.ExportPrivateKey(keyid)
fmt.Println(pubkey)
fmt.Println(privkey)
gpg.ChangePasskey(keyid, "mypassphrase", "mynewpassphrase")
```

See the documentation bellow for all the methods. Also, this is a small library,
take a look at the code!

## Documentation

The documentation is available at
[godoc.org](http://godoc.org/github.com/pelletier/go-gnupg).

## Contribute

Feel free to report bugs and patches using GitHub's pull requests system on
[pelletier/go-gnupg](https://github.com/pelletier/go-gnupg). Any feedback would
be much appreciated!

### Run tests

    go test

## License

Copyright (c) 2014 Thomas Pelletier

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
