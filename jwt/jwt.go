package jwt

import (
	"errors"
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

type JwtClaims struct {
	*jwt.StandardClaims
	UserId      string
	DomainId    string
	OrgUnitId   string
	Authorities string `json:"authorities"`
}

var (
	key []byte = []byte("showntop@163.com-jwt")
)

func GenToken(user_id, domain_id, org_id string, dt int64) (string, error) {
	fmt.Println(time.Now().Unix())
	claims := JwtClaims{
		&jwt.StandardClaims{
			ExpiresAt: time.Now().Unix() + dt,
			Issuer:    "showntop",
		},
		user_id,
		domain_id,
		org_id,
		"ROLE_ADMIN,AUTH_WRITE,ACTUATOR",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(key)
	if err != nil {
		return "", err
	}
	return ss, nil
}

func DestoryToken() (string, error) {

	claims := JwtClaims{
		&jwt.StandardClaims{
			ExpiresAt: int64(time.Now().Unix() - 99999),
			Issuer:    "hzwy23",
		},
		"exit",
		"exit",
		"exit",
		"ROLE_ADMIN,AUTH_WRITE,ACTUATOR",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(key)
	if err != nil {
		return "", err
	}
	return ss, nil
}

func CheckToken(token string) (bool, error) {
	_, err := jwt.Parse(token, func(*jwt.Token) (interface{}, error) {
		return key, nil
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

func ParseJwt(token string) (*JwtClaims, error) {
	var jclaim = &JwtClaims{}
	_, err := jwt.ParseWithClaims(token, jclaim, func(*jwt.Token) (interface{}, error) {
		return key, nil
	})
	if err != nil {
		return nil, errors.New("parase with claims failed.")
	}
	return jclaim, nil
}
