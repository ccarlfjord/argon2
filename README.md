# argon2

A small Go package for Argon2id password hashing with sane defaults.

Wraps `golang.org/x/crypto/argon2` and provides default parameters based on the
[RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) recommendations, constant-time
password validation, and cryptographically secure salt generation. The API is
inspired by the simplicity of [`golang.org/x/crypto/bcrypt`](https://pkg.go.dev/golang.org/x/crypto/bcrypt)'s
`GenerateFromPassword`/`CompareHashAndPassword` interface — one call to hash,
one call to validate — but uses Argon2id under the hood.

## Install

```sh
go get github.com/ccarlfjord/argon2
```

## Usage

### With defaults

```go
package main

import (
	"fmt"
	"log"

	"github.com/ccarlfjord/argon2"
)

func main() {
	salt := argon2.GenerateSalt()
	hash := argon2.HashPassword("correct horse battery staple", salt)

	if err := argon2.Validate("correct horse battery staple", hash, salt); err != nil {
		log.Fatal("invalid password")
	}

	fmt.Println("password is valid")
}
```

### With custom parameters

```go
params := argon2.NewArgon2idWithParams(128*1024, 4, 4, 32, 32)

salt := params.GenerateSalt()
hash := params.Hash("my password", salt)

err := params.Validate("my password", hash, salt)
```

## Parameters

| Parameter     | Default             | Description                          |
| ------------- | ------------------- | ------------------------------------ |
| `Memory`      | 64 MiB (64 * 1024)  | Memory cost in KiB                   |
| `Iterations`  | 3                   | Time cost (number of passes)         |
| `Parallelism` | 4                   | Number of parallel threads           |
| `SaltLength`  | 16 bytes            | Length of generated salts            |
| `KeyLength`   | 32 bytes            | Length of the derived key            |

Tune these upward as hardware allows. If you change parameters after hashing
passwords, you must re-hash stored passwords or track the parameters used per
hash.

## Notes

- `Validate` uses a constant-time comparison to prevent timing attacks.
- This package returns raw hash and salt bytes rather than the PHC string
  format (`$argon2id$v=19$m=...`), so callers are responsible for persisting
  the salt and hash alongside each other.

## License

[Apache License 2.0](LICENSE)
