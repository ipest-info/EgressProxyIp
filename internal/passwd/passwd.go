// Package passwd 生成和校验管理员密码。
package passwd

import (
	"crypto/rand"

	"golang.org/x/crypto/bcrypt"
)

// Cost 是 bcrypt 的计算强度。
const Cost = 12

// Hash 生成 bcrypt 哈希。
func Hash(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), Cost)
	return string(b), err
}

// Check 校验密码与哈希是否匹配。
func Check(hash, pw string) bool {
	return hash != "" && bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// Random 生成 16 位随机密码（去掉了易混淆的字符）。
func Random() string {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
	b := make([]byte, 16)
	rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}
