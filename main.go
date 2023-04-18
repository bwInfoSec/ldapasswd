package main

import (
	"crypto/cipher"
	"crypto/rand"
	"embed"
	"encoding/binary"
	"flag"
	"fmt"
	"html/template"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap"
	"github.com/miscreant/miscreant.go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
)

type RuntimeConfig struct {
	Cipher    cipher.AEAD
	NonceSize int
	UserDataStore AuthStore[*ldap.Conn]
	Templates map[string]*template.Template
	Static map[string][]byte
	DeauthDuration time.Duration
	IpRegex *regexp.Regexp
}

func GenerateNonce(size int) ([]byte, error) {
	if size-8 < 0 {
		err := fmt.Errorf("nonce size to small")
		log.Error().Err(err).Msg("GenerateNonce")
		return make([]byte, 0), err
	}

	// We'll use the time because that should always be unique
	mtime := time.Now()
	bmtime := make([]byte, 8)
	// bigEndian because if used as UUID only the most significant bits are altered
	binary.BigEndian.PutUint64(bmtime, uint64(mtime.UnixNano())) // this are 64 bits (8 bytes)

	// We'll fill the rest with random data
	bmrand := make([]byte, size-8)
	if _, err := io.ReadFull(rand.Reader, bmrand[:]); err != nil {
		log.Error().Err(err).Msg("GenerateNonce")
		return make([]byte, 0), err
	}

	// concat to get the nonce (fill from front is also because of possible UUID usage)
	nonce := append(bmrand[:], bmtime[:]...)
	return nonce, nil
}

// do some go embed magic to pack web content into the binary
//go:embed html/*
var webContent embed.FS

func generateRuntimeConfig(rconfig *RuntimeConfig) *RuntimeConfig {
	// set nonce size
	rconfig.NonceSize = 32

	// generate crypto key for cookies
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		log.Fatal().Stack().Err(err).Msg("generateRuntimeConfig")
	}

	// generate crypto context
	aessiv, err := miscreant.NewAEAD("AES-SIV", key, rconfig.NonceSize)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("generateRuntimeConfig")
	}
	// set crypto context
	rconfig.Cipher = aessiv

	// generate UserDataStore connection store
	rconfig.UserDataStore = AuthStore[*ldap.Conn]{lock: sync.RWMutex{}, userData: map[[32]byte]AuthStoreEntry[*ldap.Conn]{}}

	// set DeauthDuration
	rconfig.DeauthDuration = time.Duration(CConfig.Webserver.UserDeauthTime) * time.Minute

	// set IpRegexp
	rconfig.IpRegex = regexp.MustCompile(`((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}`)

	//
	// load static files:
	//
	rconfig.Static = make(map[string][]byte)
	// bootstrap:
	content, err := webContent.ReadFile("html/static/bootstrap.min.css")
	if err != nil {
		log.Fatal().Err(err).Msg("generateRuntimeConfig")
	}
	rconfig.Static["bootstrap"] = content
	// logo:
	content, err = webContent.ReadFile("html/static/logo.svg")
	if err != nil {
		log.Fatal().Err(err).Msg("generateRuntimeConfig")
	}
	rconfig.Static["logo"] = content
	// favicon:
	content, err = webContent.ReadFile("html/static/favicon.ico")
	if err != nil {
		log.Fatal().Err(err).Msg("generateRuntimeConfig")
	}
	rconfig.Static["favicon"] = content


	//
	// load templates:
	//
	rconfig.Templates = make(map[string]*template.Template)
	// redirect:
	templateStr, err := webContent.ReadFile("html/templates/redirect.html")
	if err != nil {
		log.Fatal().Err(err).Msg("generateRuntimeConfig")
	}
	rconfig.Templates["redirect"] = template.Must(template.New("redirect").Parse(string(templateStr)))
	// login_form
	templateStr, err = webContent.ReadFile("html/templates/login_form.html")
	if err != nil {
		log.Fatal().Err(err).Msg("generateRuntimeConfig")
	}
	rconfig.Templates["login_form"] = template.Must(template.New("login_form").Parse(string(templateStr)))
	// chpwd_form
	templateStr, err = webContent.ReadFile("html/templates/change_pwd_form.html")
	if err != nil {
		log.Fatal().Err(err).Msg("generateRuntimeConfig")
	}
	rconfig.Templates["change_pwd_form"] = template.Must(template.New("change_pwd_form").Parse(string(templateStr)))
	// chpwd_success
	templateStr, err = webContent.ReadFile("html/templates/change_pwd_success.html")
	if err != nil {
		log.Fatal().Err(err).Msg("generateRuntimeConfig")
	}
	rconfig.Templates["change_pwd_success"] = template.Must(template.New("change_pwd_success").Parse(string(templateStr)))

	return rconfig
}

var RConfig = new(RuntimeConfig)
var CConfig = new(Config)

func cleanupUserData() {

	for {
		time.Sleep(RConfig.DeauthDuration/2)
		RConfig.UserDataStore.Cleanup(RConfig.DeauthDuration)
	}
}

func main() {
	err := error(nil)
	// setup logging
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	output.FormatLevel = func(i interface{}) string {
		return strings.ToUpper(fmt.Sprintf("| %-6s|", i))
	}
	log.Logger = log.With().Caller().Logger()
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	log.Logger = log.Level(zerolog.DebugLevel)

	// parse command line variables
	var configFilePathPtr = flag.String("c", "goldap.ini", "CConfig file path")
	flag.Parse()

	// load config into global variable
	err = ReadINI(*configFilePathPtr, CConfig)
	if err != nil {
		log.Fatal().Stack().Err(err).Msg("main")
	}

	log.Debug().Interface("CConfig", CConfig).Msg("Global config")

	// create global runtime config
	generateRuntimeConfig(RConfig)

	// schedule constant cleanup
	go cleanupUserData()

	// start webserver
	RunWebServer()
}
