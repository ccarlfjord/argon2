package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"log/slog"
	"time"

	"golang.org/x/crypto/argon2"
)

var DefaultArgon2id = NewDefaultArgon2id()

type Argon2idParams struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

func NewDefaultArgon2id() *Argon2idParams {
	// RFC 9106 recommendations
	return &Argon2idParams{
		Memory:      64 * 1024, // 64MB
		Iterations:  3,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
}

func NewArgon2idWithParams(memory uint32, iterations uint32, parallelism uint8, saltLength uint32, keyLength uint32) *Argon2idParams {
	return &Argon2idParams{
		Memory:      memory,
		Iterations:  iterations,
		Parallelism: parallelism,
		SaltLength:  saltLength,
		KeyLength:   keyLength,
	}
}

func (a *Argon2idParams) Hash(password string, salt []byte) []byte {
	return argon2.IDKey(
		[]byte(password),
		salt,
		a.Iterations,
		a.Memory,
		a.Parallelism,
		a.KeyLength,
	)
}

func (a *Argon2idParams) Validate(password string, hashedPassword []byte, salt []byte) error {
	start := time.Now()
	defer func() {
		slog.Debug("password validation complete", "time", time.Since(start).String())
	}()
	h := a.Hash(password, salt)
	if subtle.ConstantTimeCompare(h, hashedPassword) == 1 {
		return nil
	}
	return errors.New("password does not match")
}

func (a *Argon2idParams) GenerateSalt() []byte {
	salt := make([]byte, a.SaltLength)
	rand.Read(salt)
	return salt
}

func HashPassword(password string, salt []byte) []byte {
	return DefaultArgon2id.Hash(password, salt)
}

func Validate(password string, hashedPassword []byte, salt []byte) error {
	return DefaultArgon2id.Validate(password, hashedPassword, salt)
}

func GenerateSalt() []byte {
	return DefaultArgon2id.GenerateSalt()
}
