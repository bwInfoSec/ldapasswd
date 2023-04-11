package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type AuthStoreEntry struct {
	userName string
	timeStamp int64
	userData interface {}
}


type AuthStore struct {
    userData map[[32]byte]AuthStoreEntry
	lock sync.RWMutex
}


func CreateAuthStoreID(userName string, timeStamp int64) [32]byte {
	input := fmt.Sprintf("%s %d", userName, timeStamp)
	return sha256.Sum256([]byte(input))
}

func (as *AuthStore) Add(userName string, timeStamp int64, userData interface{}) ([32]byte, error) {
	id := CreateAuthStoreID(userName, timeStamp)
	as.lock.Lock()
	entry, isPresent := as.userData[id]
	if isPresent {
		err := errors.New("entry already in AuthStore")
		log.Debug().Interface("entry", entry).Err(err).Msg("AuthStore.Add")
		return [32]byte{}, err
	}
	as.userData[id] = AuthStoreEntry{userName, timeStamp, userData}
	as.lock.Unlock()
	return id, nil
}

func (as *AuthStore) AddFromCookie(cookie AuthCookie, userData interface{}) ([32]byte, error) {
	return as.Add(cookie.Username, cookie.CreationTime, userData)
}

func (as *AuthStore) Cleanup(timeValid time.Duration) {
	as.lock.Lock()

	var userkeys = map[string][32]byte{}
	var del = [][32]byte{}

	for key, val := range as.userData {
		if time.UnixMicro(val.timeStamp).Add(timeValid).Before(time.Now()) {
			log.Debug().Msg("AuthStore.Cleanup: found expired entry")
			del = append(del, key)
		} else {
			storedKey, isPresent := userkeys[val.userName]
			if isPresent {
				log.Debug().Msg("AuthStore.Cleanup: found duplicate entry for \""+val.userName+"\"")
				if val.timeStamp > as.userData[storedKey].timeStamp {
					userkeys[val.userName] = key
					del = append(del, storedKey)
				} else {
					del = append(del, key)
				}
			} else {
				userkeys[val.userName] = key
			}
		}
	}

	for key := range del {
		delete(as.userData, del[key])
	}

	as.lock.Unlock()
}

func (as *AuthStore) GetUserDataFromCookie(cookie *AuthCookie) (interface{}, [32]byte, error) {

	id := CreateAuthStoreID(cookie.Username, cookie.CreationTime)

	userData := as.GetUserDataFromId(id)

	if userData != nil {
		return userData, id, nil
	} else {
		err := errors.New("invalid cookie")
		log.Debug().Str("user name", cookie.Username).Int64("creation time", cookie.CreationTime).Err(err).Msg("GetUserDataFromCookie")
		return nil, id, err
	}
}

func (as *AuthStore) GetUserData(userName string, timeStamp int64) (interface{}, [32]byte) {
	id := CreateAuthStoreID(userName, timeStamp)
	return as.GetUserDataFromId(id), id
}

func (as *AuthStore) GetUserDataFromId(authStoreId [32]byte) interface{} {
	as.lock.RLock()
	asEntry, isPresent := as.userData[authStoreId]
	as.lock.RUnlock()
	if isPresent{
		return asEntry.userData
	} else {
		return nil
	}
}

func (as *AuthStore) PopUserDataFromCookie(cookie *AuthCookie) (interface{}, error) {

	id := CreateAuthStoreID(cookie.Username, cookie.CreationTime)

	userData := as.PopUserDataFromId(id)

	if userData != nil {
		return userData, nil
	} else {
		err := errors.New("invalid cookie")
		log.Debug().Str("user name", cookie.Username).Int64("creation time", cookie.CreationTime).Err(err).Msg("PopUserDataFromCookie")
		return nil, err
	}
}

func (as *AuthStore) PopUserData(userName string, timeStamp int64) interface{} {
	id := CreateAuthStoreID(userName, timeStamp)
	return as.PopUserDataFromId(id)
}

func (as *AuthStore) PopUserDataFromId(authStoreId [32]byte) interface{} {
	as.lock.Lock()
	asEntry, isPresent := as.userData[authStoreId]
	if isPresent{
		delete(as.userData, authStoreId)
		as.lock.Unlock()
		return asEntry.userData
	} else {
		as.lock.Unlock()
		return nil
	}
}

func (as *AuthStore) DeleteEntry(authStoreId [32]byte) error {
	as.lock.Lock()

	_, isPresent := as.userData[authStoreId]
	var err error

	if isPresent {
		delete(as.userData, authStoreId)
	} else {
		err = errors.New("authStoreId not in userData")
		log.Debug().Err(err).Msg("DeleteEntry")
	}

	as.lock.Unlock()
	return err
}

