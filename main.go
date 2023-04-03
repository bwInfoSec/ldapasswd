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
	"strings"
	"sync"
	"time"

	"github.com/miscreant/miscreant.go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type RuntimeConfig struct {
	Cipher    cipher.AEAD
	NonceSize int
	LdapStore *LdapConnStore
	Templates map[string]*template.Template
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

// do some go embed magic to pack templates into the binary
//go:embed html/templates/*
var templatedWebContent embed.FS

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

	// generate LDAP connection store
	rconfig.LdapStore = new(LdapConnStore)
	rconfig.LdapStore.Lock = sync.RWMutex{}
	rconfig.LdapStore.data = map[UUID]LdapConnEntry{}

	//
	// load templates:
	//
	rconfig.Templates = make(map[string]*template.Template)
	// redirect:
	templateStr, err := templatedWebContent.ReadFile("html/templates/redirect.html")
	if err != nil {
		log.Fatal().Err(err).Msg("generateRuntimeConfig")
	}
	rconfig.Templates["redirect"] = template.Must(template.New("redirect").Parse(string(templateStr)))
	// login_form
	templateStr, err = templatedWebContent.ReadFile("html/templates/login_form.html")
	if err != nil {
		log.Fatal().Err(err).Msg("generateRuntimeConfig")
	}
	rconfig.Templates["login_form"] = template.Must(template.New("login_form").Parse(string(templateStr)))
	// chpwd_form
	templateStr, err = templatedWebContent.ReadFile("html/templates/change_pwd_form.html")
	if err != nil {
		log.Fatal().Err(err).Msg("generateRuntimeConfig")
	}
	rconfig.Templates["chpwd_form"] = template.Must(template.New("change_pwd_form").Parse(string(templateStr)))
	// chpwd_success
	templateStr, err = templatedWebContent.ReadFile("html/templates/change_pwd_success.html")
	if err != nil {
		log.Fatal().Err(err).Msg("generateRuntimeConfig")
	}
	rconfig.Templates["chpwd_success"] = template.Must(template.New("change_pwd_success").Parse(string(templateStr)))

	// reset_pwd_form
	templateStr, err = templatedWebContent.ReadFile("html/templates/reset_pwd_form.html")
	if err != nil {
		log.Fatal().Err(err).Msg("generateRuntimeConfig")
	}
	rconfig.Templates["resetpwd_form"] = template.Must(template.New("reset_pwd_form").Parse(string(templateStr)))

	return rconfig
}

var RConfig = new(RuntimeConfig)
var CConfig = new(Config)

func main() {
	err := error(nil)
	// setup logging
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

	// start webserver
	RunWebServer()
}
