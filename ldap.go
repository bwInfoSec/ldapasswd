package main

import (
	"crypto/tls"
	"fmt"
	"github.com/go-ldap/ldap"
	"github.com/rs/zerolog/log"
)

func CreateLdapConn(dn string, password string) (*ldap.Conn, error) {

	err := error(nil)
	var l *ldap.Conn

	tlsConfig := &tls.Config{}
	if CConfig.LDAP.Server.SkipTlsVerify {
		tlsConfig = &tls.Config{InsecureSkipVerify: true}
	} else {
		tlsConfig = &tls.Config{ServerName: CConfig.LDAP.Server.Host}
	}

	switch CConfig.LDAP.Server.Security {
	case "TLS":
		log.Debug().Msg(fmt.Sprintf("ldaps://%s:%d", CConfig.LDAP.Server.Host, CConfig.LDAP.Server.Port))
		l, err = ldap.DialTLS("tcp",
			fmt.Sprintf("%s:%d", CConfig.LDAP.Server.Host, CConfig.LDAP.Server.Port), tlsConfig)
		if err != nil {
			log.Error().Stack().Err(err).Msg("GetLdapConn")
			return nil, err
		}
	case "NONE", "STARTTLS":
		ldapUrl := fmt.Sprintf("ldap://%s:%d", CConfig.LDAP.Server.Host, CConfig.LDAP.Server.Port)
		log.Debug().Msg("using " + ldapUrl)
		l, err = ldap.DialURL(ldapUrl)
		if err != nil {
			log.Error().Stack().Err(err).Msg("GetLdapConn")
			return nil, err
		}
		if CConfig.LDAP.Server.Security == "STARTTLS" {
			log.Debug().Msg("using STARTTLS")
			err = l.StartTLS(tlsConfig)
			if err != nil {
				log.Error().Stack().Err(err).Msg("GetLdapConn")
				return nil, err
			}
		}
	default:
		err = fmt.Errorf("CConfig contains invalid value")
		log.Error().Stack().Str("CConfig.LDAP.Server.Security", CConfig.LDAP.Server.Security).
			Err(err).Msg("GetLdapConn")
		return nil, err
	}

	// Bind and authenticate
	err = l.Bind(dn, password)
	if err != nil {
		log.Debug().Str("DN", dn).Err(err).Msg("GetLdapConn")
		return nil, err
	}

	return l, nil
}
