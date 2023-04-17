package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

type AuthCookie struct {
	Username		 string
	AdditionalData	 string
	CreationTime	 int64
	IP				 string
	PADDING			 string
}

func getPadding() string {
	ri, err := rand.Int(rand.Reader, big.NewInt(64))
	if err != nil {
		return ""
	}

	s := ""
	for i := uint64(0); i < ri.Uint64(); i++ {
		s = s + " "
	}
	return s
}

func GenerateAuthCookie(user string, additionalData string, remoteAddr string) (http.Cookie, AuthCookie, error) {
	// extract client ip
	_ip := RConfig.IpRegex.Find([]byte(remoteAddr))
	if _ip == nil {
		err := errors.New("remoteAddr is not IP:port")
		log.Error().Err(err).Str("remoteAddr", remoteAddr).Msg("GenerateAuthCookie")
		return http.Cookie{}, AuthCookie{}, err
	}
	ip := string(_ip)

	// create cookie data object
	cookieData := AuthCookie{user, additionalData, time.Now().UnixMicro(), ip, getPadding()}

	httpCookie, err := cookieData.ToHttpCookie()
	if err != nil {
		log.Error().Err(err).Msg("GenerateAuthCookie")
		return http.Cookie{}, AuthCookie{}, err
	}

	return httpCookie, cookieData, nil
}


func (cookieData *AuthCookie) ToHttpCookie() (http.Cookie, error) {

	// serialize cookieData into JSON
	jdata, err := json.Marshal(cookieData)
	if err != nil {
		log.Error().Err(err).Msg("AuthCookie.ToHttpCookie")
		return http.Cookie{}, err
	}

	// generate nonce for encrytion
	nonce, err := GenerateNonce(RConfig.NonceSize)
	if err != nil {
		log.Error().Err(err).Msg("AuthCookie.ToHttpCookie")
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

func (cookie *AuthCookie) VerifyExpired(timeValid time.Duration) error {
	if time.UnixMicro(cookie.CreationTime).Add(timeValid).Before(time.Now()) {
		err := errors.New("cookie expired")
		log.Debug().Interface("cookie", cookie).Err(err).Msg("AuthCookie.VerifyExpired")
		return err
	}
	return nil
}

func (cookie *AuthCookie) VerifyRemote(remoteAddr string) error {
	// extract client ip
	_ip := RConfig.IpRegex.Find([]byte(remoteAddr))
	if _ip == nil {
		err := errors.New("remoteAddr is not IP:port")
		log.Error().Err(err).Interface("cookie", cookie).Str("remoteAddr", remoteAddr).Msg("AuthCookie.VerifyRemote")
		return err
	}
	ip := string(_ip)

	if cookie.IP != ip {
		err := errors.New("client ip changed")
		log.Debug().Err(err).Interface("cookie", cookie).Str("remoteAddr", remoteAddr).Msg("AuthCookie.VerifyRemote")
		return err
	}
	return nil
}

func (cookie *AuthCookie) Renew() (http.Cookie, AuthCookie, error) {
	rawCookie := AuthCookie{cookie.Username, cookie.AdditionalData, time.Now().UnixMicro(), cookie.IP, cookie.PADDING}
	newCookie, err := rawCookie.ToHttpCookie()
	if err != nil {
		log.Debug().Err(err).Msg("AuthCookie.Renew")
	}
	return newCookie, rawCookie, err
}

func GetDeauthCookie() *http.Cookie {
	return &http.Cookie{HttpOnly: true, Name: "auth", Value: "RSET", Path: "/"}
}
