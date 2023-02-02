package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"math/big"
	"net"
	"net/http"
	"time"
)

type AuthCookie struct {
	Username   string
	LdapConnId UUID
	Admin      bool
	ExpiryTime int64
	IP         string
	PADDING    string
}

func getPadding() string {
	ri, err := rand.Int(rand.Reader, big.NewInt(32))
	if err != nil {
		return ""
	}

	s := ""
	for i := uint64(0); i < ri.Uint64(); i++ {
		s = s + " "
	}
	return s
}

func GenerateAuthCookie(user string, ldapconnid UUID, admin bool, remoteAddr string) (http.Cookie, error) {
	// extract client ip
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		log.Error().Err(err).Str("remoteAddr", remoteAddr).Msg("VerifyAuthCookie: remoteAddr is not IP:port")
		return http.Cookie{}, err
	}

	// create cookie data object
	expiryTime := time.Now().Add(time.Duration(CConfig.Webserver.UserDeauthTime) * time.Minute)
	cookieData := AuthCookie{user, ldapconnid, admin, expiryTime.UnixNano(), ip, getPadding()}

	// serialize mdata into JSON
	jdata, err := json.Marshal(cookieData)
	if err != nil {
		log.Error().Err(err).Msg("GenerateAuthCookie")
		return http.Cookie{}, err
	}

	// generate nonce for encrytion
	nonce, err := GenerateNonce(RConfig.NonceSize)
	if err != nil {
		log.Error().Err(err).Msg("GenerateAuthCookie")
		return http.Cookie{}, err
	}

	// encrypt jdata
	encJdata := RConfig.Cipher.Seal(nil, nonce, jdata, nil)

	// concaternate nonce and encJdata
	encData := append(nonce[:], encJdata...)
	// encode data base64
	encCookie := base64.URLEncoding.EncodeToString(encData)

	return http.Cookie{HttpOnly: true, Name: "auth", Value: encCookie, Path: "/"}, nil
}

func DecodeAuthCookie(cookie *http.Cookie) (*AuthCookie, error) {

	authCookie := new(AuthCookie)

	// check if cookie is 'auth' cookie
	if cookie.Name != "auth" {
		err := fmt.Errorf("cookie is not 'auth' cookie")
		log.Error().Err(err).Msg("DecodeAuthCookie")
		return authCookie, err
	}

	// get encrypted cookie
	encCookie := cookie.Value

	// base64 decode encrypted cookie
	encData, err := base64.URLEncoding.DecodeString(encCookie)
	if err != nil {
		log.Error().Err(err).Msg("DecodeAuthCookie")
		return authCookie, err
	}

	// extract nonce and encrypted JSON
	nonce := encData[:RConfig.NonceSize]
	encJdata := encData[RConfig.NonceSize:]
	// decrypt JSON
	decJdata, err := RConfig.Cipher.Open(nil, nonce, encJdata, nil)
	if err != nil {
		log.Warn().Err(err).Stack().Msg("DecodeAuthCookie")
		return authCookie, err
	}

	// deserialize JSON
	err = json.Unmarshal(decJdata, authCookie)
	if err != nil {
		log.Error().Err(err).Msg("DecodeAuthCookie")
		return authCookie, err
	}

	return authCookie, nil
}

func VerifyAuthCookie(cookie *AuthCookie, remoteAddr string) (bool, error) {
	var ok = true
	if cookie.ExpiryTime < time.Now().UnixNano() {
		log.Info().Int64("now", time.Now().UnixNano()).Int64("expires", cookie.ExpiryTime).
			Interface("cookie", cookie).Msg("VerifyAuthCookie: cookie expired")
		ok = false
	}
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		errStr := "VerifyAuthCookie: remoteAddr is not IP:port"
		log.Error().Err(err).Str("remoteAddr", remoteAddr).Msg(errStr)
		return false, errors.Wrap(err, errStr)
	}
	if cookie.IP != ip {
		log.Info().Interface("cookie", cookie).Msg("VerifyAuthCookie: client ip changed")
		ok = false
	}
	return ok, nil
}

func RenewAuthCookie(cookie *AuthCookie, remoteAddr string) (http.Cookie, error) {
	ok, err := VerifyAuthCookie(cookie, remoteAddr)
	if err != nil {
		log.Error().Err(err).Msg("RenewAuthCookie")
		return http.Cookie{}, err
	}
	if !ok {
		err = fmt.Errorf("cookie verification failed")
		log.Info().Err(err).Msg("RenewAuthCookie")
		return http.Cookie{}, err
	}
	newCookie, err := GenerateAuthCookie(cookie.Username, cookie.LdapConnId, cookie.Admin, remoteAddr)
	if err != nil {
		log.Error().Err(err).Msg("RenewAuthCookie")
		return http.Cookie{}, err
	}
	return newCookie, nil
}

func GetDeauthCookie() *http.Cookie {
	return &http.Cookie{HttpOnly: true, Name: "auth", Value: "RESET", Path: "/"}
}
