package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type AuthStoreEntry[UD any] struct {
	userName  string
	timeStamp int64
	userData  UD
}

type AuthStore[UD any] struct {
	userData map[[32]byte]AuthStoreEntry[UD]
	lock     sync.RWMutex
}

func CreateAuthStoreID(userName string, timeStamp int64) [32]byte {
	input := fmt.Sprintf("%s %d", userName, timeStamp)
	return sha256.Sum256([]byte(input))
}

func (as *AuthStore[UD]) Add(userName string, timeStamp int64, userData UD) ([32]byte, error) {
	id := CreateAuthStoreID(userName, timeStamp)

	var err error = nil
	as.lock.Lock()
	_, isPresent := as.userData[id]
	if isPresent {
		err = errors.New("entry already in AuthStore")
		log.Warn().Bytes("id", id[:]).Err(err).Msg("AuthStore.Add")
	} else {
		as.userData[id] = AuthStoreEntry[UD]{userName, timeStamp, userData}
		log.Debug().Bytes("id", id[:]).Msg("AuthStore.Add")
	}
	as.lock.Unlock()
	return id, err
}

func (as *AuthStore[UD]) AddFromCookie(cookie AuthCookie, userData UD) ([32]byte, error) {
	return as.Add(cookie.Username, cookie.CreationTime, userData)
}

func (as *AuthStore[UD]) Cleanup(timeValid time.Duration) {
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
				log.Debug().Msg("AuthStore.Cleanup: found duplicate entry")
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
		log.Debug().Bytes("id", del[key][:]).Msg("AuthStore.Cleanup: deleted")
	}

	as.lock.Unlock()
}

func (as *AuthStore[UD]) GetUserDataFromCookie(cookie AuthCookie) (UD, error) {
	id := CreateAuthStoreID(cookie.Username, cookie.CreationTime)
	return as.GetUserDataFromId(id)
}

func (as *AuthStore[UD]) GetUserData(userName string, timeStamp int64) (UD, error) {
	id := CreateAuthStoreID(userName, timeStamp)
	return as.GetUserDataFromId(id)
}

func (as *AuthStore[UD]) GetUserDataFromId(authStoreId [32]byte) (UD, error) {
	as.lock.RLock()
	asEntry, isPresent := as.userData[authStoreId]
	as.lock.RUnlock()
	var err error = nil
	if isPresent {
		log.Debug().Bytes("id", authStoreId[:]).Msg("AuthStore.GetUserDataFromId: entry found")
	} else {
		err = errors.New("no data is associated with this id")
		log.Warn().Err(err).Bytes("id", authStoreId[:]).Msg("AuthStore.GetUserDataFromId")
	}
	return asEntry.userData, err
}

func (as *AuthStore[UD]) PopUserDataFromCookie(cookie AuthCookie) (UD, error) {
	id := CreateAuthStoreID(cookie.Username, cookie.CreationTime)
	return as.PopUserDataFromId(id)
}

func (as *AuthStore[UD]) PopUserData(userName string, timeStamp int64) (UD, error) {
	id := CreateAuthStoreID(userName, timeStamp)
	return as.PopUserDataFromId(id)
}

func (as *AuthStore[UD]) PopUserDataFromId(authStoreId [32]byte) (UD, error) {
	as.lock.Lock()
	asEntry, isPresent := as.userData[authStoreId]

	var err error = nil
	if isPresent {
		delete(as.userData, authStoreId)
		log.Debug().Bytes("id", authStoreId[:]).Msg("AuthStore.PopUserDataFromId: entry popped")
	} else {
		err = errors.New("no data is associated with this id")
		log.Warn().Err(err).Bytes("id", authStoreId[:]).Msg("AuthStore.PopUserDataFromId")
	}

	as.lock.Unlock()
	return asEntry.userData, err
}

func (as *AuthStore[UD]) DeleteEntry(authStoreId [32]byte) error {
	as.lock.Lock()
	_, isPresent := as.userData[authStoreId]

	var err error = nil
	if isPresent {
		delete(as.userData, authStoreId)
		log.Debug().Bytes("id", authStoreId[:]).Msg("AuthStore.DeleteEntry: entry deleted")
	} else {
		err = errors.New("no data is associated with this id")
		log.Warn().Err(err).Bytes("id", authStoreId[:]).Msg("AuthStore.DeleteEntry")
	}

	as.lock.Unlock()
	return err
}
