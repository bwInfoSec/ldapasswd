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

	http.HandleFunc("/bootstrap.min.css"		, serveCssBootstrap)
	http.HandleFunc("/logo.svg"					, serveLogo)
	http.HandleFunc("/bwinfosec_favicon.ico"	, serveFavicon)
	http.HandleFunc("/login"					, loginHandler)
	http.HandleFunc("/logout"					, logoutHandler)
	http.HandleFunc("/changepwd"				, changePasswordHandler)
	http.HandleFunc("/changepwdsuccess"			, changePasswordSuccessHandler)

	log.Info().Msg("Starting server at " + CConfig.Webserver.ListenAddress)
	if err := http.ListenAndServe(CConfig.Webserver.ListenAddress, nosurf.New(http.DefaultServeMux)); err != nil {
		log.Fatal().Stack().Err(err).Msg("RunWebServer")
	}
}

// ============== serve static stuff ================================
func serveCssBootstrap(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/css")
	fmt.Fprintf(w, "%v", RConfig.Static["bootstrap"])
}
func serveLogo(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "image/svg+xml")
	fmt.Fprintf(w, "%v", RConfig.Static["logo"])
}
func serveFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "image/x-icon")
	fmt.Fprintf(w, "%v", RConfig.Static["favicon"])
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
		claimsAdmin := false

		dn := fmt.Sprintf("%s=%s,", CConfig.LDAP.AuthDefaults.IdentifyingAttribute, username)
		dn += CConfig.LDAP.AuthDefaults.UserDnPostfix

		id, err := AddLdapConn(RConfig.LdapStore, dn, password)
		if err != nil {
			log.Debug().Err(err).Str("r.RemoteAddr", r.RemoteAddr).Msg("loginHandler: access denied")
			ctx["invalid"] = "Invalid Credentials!"
		} else {
			cookie, err := GenerateAuthCookie(username, id, claimsAdmin, r.RemoteAddr)
			if err != nil {
				log.Error().Err(err).Msg("authRequest")
			}
			http.SetCookie(w, &cookie)
			http.Redirect(w, r, "/changepwd", http.StatusSeeOther)
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

			err = LdapConnStoreDeleteEntry(RConfig.LdapStore, decCookie.LdapConnId)
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
				log.Error().Stack().Err(err).Msg("getAuthCookie")
				return nil, err
			}

			ok, err := VerifyAuthCookie(decCookie, r.RemoteAddr)

			if err == nil && ok == true {
				// All is fine; requirement fulfilled

				// update cookie
				httpCookie, err := RenewAuthCookie(decCookie, r.RemoteAddr)
				if err == nil {
					http.SetCookie(w, &httpCookie)
					return decCookie, nil
				} else {
					log.Error().Err(err).Stack().Msg("getAuthCookie")
					return decCookie, err
				}
			}
			// !! something is wrong !!
			logout(w, r)
			// error handling
			if err != nil {
				return nil, err
			}
			// ok must be false
			err = fmt.Errorf("cookie is invalid")
			log.Debug().Err(err).Msg("checkLogin")
			return decCookie, err
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
	ctx["send_to"] = "/changepwd"
	ctx["base_url"] = CConfig.Webserver.URL
	ctx["title_prefix"] = CConfig.Webserver.PageTitlePrefix

	if r.Method == "POST" {
		/******************************************************************************************************
													POST
		******************************************************************************************************/
		cookie, _ := getAuthCookie(w, r)
		conn, err := LookupLdapConn(RConfig.LdapStore, cookie.LdapConnId)
		if err != nil {
			log.Info().Str("Info", "Error finding LDAP Connection for user "+cookie.Username).Err(err).Msg("changePasswordHandler")
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
			ctx = map[string]string{"url": CConfig.Webserver.URL + "/changepwdsuccess"}
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
