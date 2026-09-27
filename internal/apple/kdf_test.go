package apple

import (
	"crypto/sha256"
	"golang.org/x/crypto/pbkdf2"
)

func deriveTestPassword(p, s []byte) []byte { return pbkdf2.Key(p, s, 1000, 32, sha256.New) }
