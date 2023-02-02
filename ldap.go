package main

import (
	"crypto/tls"
	"fmt"
	"github.com/go-ldap/ldap"
	"github.com/rs/zerolog/log"
	"sync"
	"time"
)

type UUID [16]byte

type LdapConnEntry struct {
	Conn  *ldap.Conn
	Tstmp int64
}

type LdapConnStore struct {
	Lock sync.RWMutex
	data map[UUID]LdapConnEntry
}

func LdapConnStoreCleanup(store *LdapConnStore) error {
	store.Lock.RLock()
	for key, ldapConnEntry := range store.data {
		if ldapConnEntry.Tstmp < time.Now().Add(-time.Duration(1+CConfig.Webserver.UserDeauthTime)*time.Minute).UnixNano() {
			store.Lock.RUnlock()
			err := LdapConnStoreDeleteEntry(store, key)
			if err != nil {
				log.Error().Err(err).Msg("LdapConnStoreCleanup")
				return err
			}
			store.Lock.RLock()
		}
	}
	store.Lock.RUnlock()
	return nil
}

func LdapConnStoreDeleteEntry(store *LdapConnStore, id UUID) error {
	store.Lock.RLock()
	ldapConnEntry := store.data[id]
	store.Lock.RUnlock()
	if (ldapConnEntry == LdapConnEntry{}) {
		err := fmt.Errorf("id %x was not found in LdapConnStore", id)
		log.Info().Err(err).Msg("LdapConnStoreDeleteEntry")
		return err
	}

	store.Lock.Lock()
	ldapConnEntry.Conn.Close()
	delete(store.data, id)
	store.Lock.Unlock()
	return nil
}

func LookupLdapConn(store *LdapConnStore, id UUID) (*ldap.Conn, error) {
	store.Lock.RLock()
	ldapConnEntry := store.data[id]
	store.Lock.RUnlock()

	var l *ldap.Conn = nil
	err := error(nil)
	if (ldapConnEntry == LdapConnEntry{}) {
		err = fmt.Errorf("id %x was not found in LdapConnStore", id)
		log.Info().Err(err).Msg("LookupLdapConn")
		return l, err
	}

	if ldapConnEntry.Tstmp < time.Now().Add(-time.Duration(1+CConfig.Webserver.UserDeauthTime)*time.Minute).UnixNano() {
		err = fmt.Errorf("LDAP authentication expired")
		log.Info().Err(err).Msg("LookupLdapConn")
		err = LdapConnStoreDeleteEntry(store, id)
		if err != nil {
			log.Error().Err(err).Msg("LookupLdapConn")
		}
	} else {
		l = ldapConnEntry.Conn
		store.Lock.Lock()
		store.data[id] = LdapConnEntry{
			Conn:  l,
			Tstmp: time.Now().UnixNano(),
		}
		store.Lock.Unlock()
	}

	return l, err
}

func GenUUID() (UUID, error) {
	n, err := GenerateNonce(16)
	if err != nil {
		log.Error().Err(err).Msg("GenUUID")
		return [16]byte{}, err
	}
	id := UUID{}
	copy(id[:], n)
	id[6] = (id[6] & 0x0f) | 0x40 // Version 4
	id[8] = (id[8] & 0x3f) | 0x80 // Variant is 10
	return id, nil
}

func AddLdapConn(store *LdapConnStore, dn string, password string) (UUID, error) {
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
			return UUID{}, err
		}
	case "NONE", "STARTTLS":
		ldapUrl := fmt.Sprintf("ldap://%s:%d", CConfig.LDAP.Server.Host, CConfig.LDAP.Server.Port)
		log.Debug().Msg("using " + ldapUrl)
		l, err = ldap.DialURL(ldapUrl)
		if err != nil {
			log.Error().Stack().Err(err).Msg("GetLdapConn")
			return [16]byte{}, err
		}
		if CConfig.LDAP.Server.Security == "STARTTLS" {
			log.Debug().Msg("using STARTTLS")
			err = l.StartTLS(tlsConfig)
			if err != nil {
				log.Error().Stack().Err(err).Msg("GetLdapConn")
				return [16]byte{}, err
			}
		}
	default:
		err = fmt.Errorf("CConfig contains invalid value")
		log.Error().Stack().Str("CConfig.LDAP.Server.Security", CConfig.LDAP.Server.Security).
			Err(err).Msg("GetLdapConn")
		return [16]byte{}, err
	}

	// Bind and authenticate
	err = l.Bind(dn, password)
	if err != nil {
		log.Debug().Str("DN", dn).Err(err).Msg("GetLdapConn")
		return [16]byte{}, err
	}

	// generate UUID
	id, err := GenUUID()
	if err != nil {
		log.Error().Stack().Err(err).Msg("GetLdapConn")
		return [16]byte{}, err
	}

	// add LDAP connection to the Connection store
	store.Lock.Lock()
	store.data[id] = LdapConnEntry{
		Conn:  l,
		Tstmp: time.Now().UnixNano(),
	}
	store.Lock.Unlock()

	return id, nil
}
