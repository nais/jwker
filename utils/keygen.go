package utils

import (
	"math/rand"
)

// Generate a cryptographically secure random key of N length.
// func Keygen(length int) ([]byte, error) {
// 	buf := make([]byte, length)
// 	_, err := rand.Read(buf)
// 	return buf, err
// }

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
