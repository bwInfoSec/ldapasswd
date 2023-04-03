package main

import (
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog/log"
	"gopkg.in/ini.v1"
	"os"
)

// Configuration struct for general app configuration values
type Config struct {
	Webserver struct {
		UserDeauthTime  uint   `validate:"required,gt=0,lte=1440"`
		URL             string `validate:"required,url"`
		ListenAddress   string `validate:"required,tcp_addr"`
		PageTitlePrefix string `validate:"required"`
	}
	LDAP struct {
		Server struct {
			Host          string `validate:"required,hostname"`
			Port          uint   `validate:"required,gt=0,lte=65535"`
			Security      string `validate:"required,security-enum"`
			SkipTlsVerify bool   // do not validate because https://github.com/go-playground/validator/issues/319git
		}
		AuthDefaults struct {
			IdentifyingAttribute string `validate:"required"`
			UserDnPostfix        string `validate:"required"`
		}
	}
}

func ValidateSecurityEnum(fl validator.FieldLevel) bool {
	return fl.Field().String() == "NONE" || fl.Field().String() == "TLS" || fl.Field().String() == "STARTTLS"
}

func ReadINI(configPath string, configPointer *Config) error {

	// Check if config file exists
	err := validateConfigPath(configPath)
	if err != nil {
		log.Error().Err(err).Msg("ReadINI")
	}

	// read INI file
	cfg, err := ini.Load(configPath)
	if err != nil {
		log.Error().Err(err).Msg("ReadINI")
		return err
	}

	// move INI file Contents to Config struct
	err = readLdapServer(cfg, configPointer)
	if err != nil {
		log.Error().Err(err).Msg("ReadINI")
		return err
	}
	err = readLdapAuth(cfg, configPointer)
	if err != nil {
		log.Error().Err(err).Msg("ReadINI")
		return err
	}
	err = readWebserver(cfg, configPointer)
	if err != nil {
		log.Error().Err(err).Msg("ReadINI")
		return err
	}

	validate := validator.New()

	err = validate.RegisterValidation("security-enum", ValidateSecurityEnum)
	if err != nil {
		log.Error().Err(err).Msg("ReadINI")
		return err
	}

	err = validate.Struct(configPointer)
	if err != nil {
		log.Error().Err(err).Interface("Config", configPointer).Msg("ReadINI")
		return err
	}

	return nil
}

func readWebserver(cfg *ini.File, configPointer *Config) error {
	err := error(nil)

	configPointer.Webserver.UserDeauthTime, err = cfg.Section("webserver").Key("user_deauth_time").Uint()
	if err != nil {
		log.Error().Err(err).Msg("readWebserver")
		return err
	}
	configPointer.Webserver.URL = cfg.Section("webserver").Key("url").String()
	configPointer.Webserver.ListenAddress = cfg.Section("webserver").Key("listen_address").String()
	configPointer.Webserver.PageTitlePrefix = cfg.Section("webserver").Key("page_title_prefix").String()

	return err
}

func readLdapAuth(cfg *ini.File, configPointer *Config) error {
	err := error(nil)

	configPointer.LDAP.AuthDefaults.IdentifyingAttribute = cfg.Section("LDAP-auth").Key("primary_attribute").String()
	configPointer.LDAP.AuthDefaults.UserDnPostfix = cfg.Section("LDAP-auth").Key("user_DN_postfix").String()
	return err
}

func readLdapServer(cfg *ini.File, configPointer *Config) error {
	err := error(nil)

	configPointer.LDAP.Server.Host = cfg.Section("LDAP-server").Key("host").String()
	configPointer.LDAP.Server.Port, err = cfg.Section("LDAP-server").Key("port").Uint()
	if err != nil {
		log.Error().Err(err).Msg("readLdapServer")
		return err
	}
	configPointer.LDAP.Server.Security = cfg.Section("LDAP-server").Key("security").String()
	configPointer.LDAP.Server.SkipTlsVerify, err = cfg.Section("LDAP-server").Key("skip_TLS_verify").Bool()
	if err != nil {
		log.Error().Err(err).Msg("readLdapServer")
		return err
	}

	return err
}

// ValidateConfigPath just makes sure, that the path provided is a file, that can be read
func validateConfigPath(path string) error {
	s, err := os.Stat(path)
	if err != nil {
		log.Error().Err(err).Msg("ValidateConfigPath")
		return err
	}
	if s.IsDir() {
		err = fmt.Errorf("'%s' is a directory, not a normal file", path)
		log.Error().Err(err).Msg("ValidateConfigPath")
		return err
	}
	return nil
}
