package butterflymxtest

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 default for authenticator apps.
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"time"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func newTOTPSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return b32.EncodeToString(b)
}

// totpCode computes the RFC 6238 code (SHA1, 30 s step, 6 digits) for the
// given secret and time-step counter.
func totpCode(secret string, counter int64) string {
	key, err := b32.DecodeString(secret)
	if err != nil {
		return ""
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000)
}

// totpValid reports whether code is valid for the window containing now, or
// either neighbouring window.
func totpValid(secret, code string, now time.Time) bool {
	c := now.Unix() / 30
	for d := int64(-1); d <= 1; d++ {
		if hmac.Equal([]byte(totpCode(secret, c+d)), []byte(code)) {
			return true
		}
	}
	return false
}
