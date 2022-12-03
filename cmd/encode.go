package cmd

import (
	"math/rand"
	"time"
)

func RandomString() string {
	rand.Seed(time.Now().UnixNano())

	charset := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, 32)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}

	return string(b)
}
