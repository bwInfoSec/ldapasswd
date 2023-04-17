package main

import (
	_ "embed"
	"fmt"
	"net/http"

	"github.com/go-ldap/ldap"
	"github.com/justinas/nosurf"
	"github.com/rs/zerolog/log"
)

// ===================== HTTP routing ===============================

func RunWebServer() {
	http.Handle("/"				, http.RedirectHandler(CConfig.Webserver.URL+"/login", http.StatusMovedPermanently))
	http.Handle("/index.html"	, http.RedirectHandler(CConfig.Webserver.URL+"/login", http.StatusMovedPermanently))

	http.HandleFunc("/bootstrap.min.css"	, serveCssBootstrap)
	http.HandleFunc("/logo.svg"				, serveLogo)
	http.HandleFunc("/favicon.ico"			, serveFavicon)
	http.HandleFunc("/login"				, loginHandler)
	http.HandleFunc("/logout"				, logoutHandler)
	http.HandleFunc("/change_pwd"			, changePasswordHandler)
	http.HandleFunc("/change_pwd_success"	, changePasswordSuccessHandler)

	log.Info().Msg("Starting server at " + CConfig.Webserver.ListenAddress)
	if err := http.ListenAndServe(CConfig.Webserver.ListenAddress, nosurf.New(http.DefaultServeMux)); err != nil {
		log.Fatal().Stack().Err(err).Msg("RunWebServer")
	}
}

// ============== serve static stuff ================================
func serveCssBootstrap(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/css")
	w.Write(RConfig.Static["bootstrap"])
}
func serveLogo(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "image/svg+xml")
	w.Write(RConfig.Static["logo"])
}
func serveFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "image/x-icon")
	w.Write(RConfig.Static["favicon"])
}


// ============== serve dynamic stuff ===============================
func loginHandler(w http.ResponseWriter, r *http.Request) {

	// create context for template
	ctx := make(map[string]string)
	ctx["token"] = nosurf.Token(r)
	ctx["send_to"] = "/login"
	ctx["title_prefix"] = CConfig.Webserver.PageTitlePrefix

	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			log.Error().Err(err).Msg("loginHandler")
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		dn := fmt.Sprintf("%s=%s,", CConfig.LDAP.AuthDefaults.IdentifyingAttribute, username)
		dn += CConfig.LDAP.AuthDefaults.UserDnPostfix

		conn, err := CreateLdapConn(dn, password)
		if err != nil {
			log.Debug().Err(err).Str("r.RemoteAddr", r.RemoteAddr).Msg("loginHandler: access denied")
			ctx["invalid"] = "Invalid Credentials!"
		} else {
			cookie, cookieData, err := GenerateAuthCookie(username, "", r.RemoteAddr)
			if err != nil {
				log.Error().Err(err).Msg("loginHandler")
				return
			}
			_, err = RConfig.UserDataStore.AddFromCookie(cookieData, conn)
			if err != nil {
				log.Error().Err(err).Msg("loginHandler")
				return
			}

			http.SetCookie(w, &cookie)
			http.Redirect(w, r, "/change_pwd", http.StatusSeeOther)
			return
		}
	}

	// fill in template parameter and execute it
	err := RConfig.Templates["login_form"].Execute(w, ctx)
	if err != nil {
		log.Error().Err(err).Msg("loginHandler")
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func changePasswordSuccessHandler(w http.ResponseWriter, r *http.Request) {
	logout(w, r)
	// Set URL to redirect to as CTX
	ctx := make(map[string]string)
	ctx["title_prefix"] = CConfig.Webserver.PageTitlePrefix

	// Execute Template
	err := RConfig.Templates["change_pwd_success"].Execute(w, ctx)
	if err != nil {
		log.Error().Err(err).Msg("changePasswordSuccessHandler")
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
	return
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	logout(w, r)
	// Set URL to redirect to as CTX
	ctx := make(map[string]string)
	ctx["url"] = CConfig.Webserver.URL + "/"
	ctx["title_prefix"] = CConfig.Webserver.PageTitlePrefix

	// Execute Template
	err := RConfig.Templates["redirect"].Execute(w, ctx)
	if err != nil {
		log.Error().Err(err).Msg("logoutHandler")
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
	return
}

func logout(w http.ResponseWriter, r *http.Request) {
	// search auth cookie
	cookies := r.Cookies()
	for _, c := range cookies {
		if c.Name == "auth" {
			decCookie, err := DecodeAuthCookie(c)
			if err != nil || decCookie == nil {
				log.Error().Stack().Err(err).Msg("logout")
				http.SetCookie(w, GetDeauthCookie())
				return
			}

			_, err = RConfig.UserDataStore.PopUserDataFromCookie(decCookie)
			if err != nil {
				log.Error().Stack().Err(err).Msg("logout")
			}
			http.SetCookie(w, GetDeauthCookie())
			return
		}
	}
}

func checkLogin(w http.ResponseWriter, r *http.Request) error {
	_, err := getAuthCookie(w, r)
	return err
}

func getAuthCookie(w http.ResponseWriter, r *http.Request) (*AuthCookie, error) {
	// search and validate auth cookie
	cookies := r.Cookies()
	for _, c := range cookies {
		if c.Name == "auth" {
			decCookie, err := DecodeAuthCookie(c)
			if err != nil || decCookie == nil {
				log.Error().Err(err).Msg("getAuthCookie")
				logout(w, r)
				return nil, err
			}

			err = decCookie.VerifyRemote(r.RemoteAddr)
			if err != nil {
				log.Error().Err(err).Msg("getAuthCookie")
				logout(w, r)
				return nil, err
			}
			err = decCookie.VerifyExpired(RConfig.DeauthDuration)
			if err != nil {
				log.Error().Err(err).Msg("getAuthCookie")
				logout(w, r)
				return nil, err
			}

			// first sanity checks are ok; now check if cookie is consistent with local data

			// remove old entry in local data store
			userData, err := RConfig.UserDataStore.PopUserDataFromCookie(decCookie)
			if err != nil {
				log.Error().Err(err).Msg("getAuthCookie")
				logout(w, r)
				return nil, err
			}

			// everything seems fine; update cookie
			httpCookie, rawCookie, err := decCookie.Renew()
			if err != nil {
				log.Error().Err(err).Msg("getAuthCookie")
				logout(w, r)
				return nil, err
			}

			// add entry back into local data store
			_, err = RConfig.UserDataStore.AddFromCookie(rawCookie, userData)
			if err != nil {
				log.Error().Err(err).Msg("getAuthCookie")
				logout(w, r)
				return nil, err
			}
			http.SetCookie(w, &httpCookie)
			return decCookie, nil
		}
	}
	err := fmt.Errorf("user is not logged in")
	log.Debug().Err(err).Msg("checkLogin")
	return nil, err
}

func requireLogin(w http.ResponseWriter, r *http.Request) error {
	err := checkLogin(w, r)
	if err != nil {
		// Set URL to redirect to as CTX
		ctx := make(map[string]string)
		ctx["url"] = CConfig.Webserver.URL + "/login"

		// Execute Template
		err2 := RConfig.Templates["redirect"].Execute(w, ctx)
		if err2 != nil {
			log.Error().Err(err2).Msg("settingsMenuHandler")
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return err
		}
		return err
	}
	return nil
}

func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	err := requireLogin(w, r)
	if err != nil {
		return
	}
	ctx := make(map[string]string)
	ctx["token"] = nosurf.Token(r)
	ctx["send_to"] = "/change_pwd"
	ctx["base_url"] = CConfig.Webserver.URL
	ctx["title_prefix"] = CConfig.Webserver.PageTitlePrefix

	if r.Method == "POST" {
		/******************************************************************************************************
													POST
		******************************************************************************************************/
		cookie, _ := getAuthCookie(w, r)
		_conn, _, err := RConfig.UserDataStore.GetUserDataFromCookie(cookie)
		conn, ok := _conn.(*ldap.Conn)
		if err != nil || ok != true {
			log.Error().Str("Info", "Error finding LDAP Connection for logged in user ").Err(err).Msg("changePasswordHandler")
			RConfig.UserDataStore.Cleanup(RConfig.DeauthDuration)
			// Set URL to redirect to as CTX
			ctx = map[string]string{"url": CConfig.Webserver.URL + "/login"}
			// Execute Template
			err = RConfig.Templates["redirect"].Execute(w, ctx)
			if err != nil {
				log.Error().Err(err).Msg("changePasswordHandler")
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			return
		}
		dn := fmt.Sprintf("%s=%s,", CConfig.LDAP.AuthDefaults.IdentifyingAttribute, cookie.Username)
		dn += CConfig.LDAP.AuthDefaults.UserDnPostfix

		if conn != nil {
			oldPassword := r.FormValue("pwd_old")
			newPassword := r.FormValue("pwd_new")
			newPasswordConf := r.FormValue("pwd_new2")

			if newPassword != newPasswordConf {
				err_str := "Password and confirmation are not the same!"
				log.Info().Msg("changePasswordHandler: " + err_str)
				ctx["invalid"] = err_str
				err := RConfig.Templates["change_pwd_form"].Execute(w, ctx)
				if err != nil {
					log.Error().Err(err).Msg("changePasswordHandler")
					http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
					return
				}
			}

			pwdModReq := ldap.NewPasswordModifyRequest(dn, oldPassword, newPassword)

			_, err = conn.PasswordModify(pwdModReq)
			if err != nil {
				log.Error().Err(err).Msg("changePasswordHandler")
				ctx["invalid"] = err.Error()
				err = RConfig.Templates["change_pwd_form"].Execute(w, ctx)
				if err != nil {
					log.Error().Err(err).Msg("changePasswordHandler")
					http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
					return
				}
				return
			}
			// Password change was successful
			log.Info().Str("User", cookie.Username).Msg("changePasswordHandler: successfully changed password")
			ctx = map[string]string{"url": CConfig.Webserver.URL + "/change_pwd_success"}
			err = RConfig.Templates["redirect"].Execute(w, ctx)
			if err != nil {
				log.Error().Err(err).Msg("changePasswordHandler")
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			return
		}
	} else if r.Method == "GET" {
		/******************************************************************************************************
													GET
		******************************************************************************************************/
		err := RConfig.Templates["change_pwd_form"].Execute(w, ctx)
		if err != nil {
			log.Error().Err(err).Msg("changePasswordHandler")
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		log.Info().Err(fmt.Errorf("not allowed HTTP method from %s", r.RemoteAddr)).Msg("settingsMenuHandler")
		return
	}
}
