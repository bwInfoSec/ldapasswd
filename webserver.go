package main

import (
	_ "embed"
	"fmt"
	"net/http"
	"sort"

	"github.com/go-ldap/ldap"
	"github.com/justinas/nosurf"
	"github.com/rs/zerolog/log"
)

// ============== embed and serve static stuff =====================
//go:embed html/static/bootstrap.min.css
var cssBootstrap string

//go:embed html/static/logo.svg
var logo string

//go:embed html/static/bwinfosec_favicon.ico
var favicon string

func serveCssBootstrap(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/css")
	fmt.Fprintf(w, "%v", cssBootstrap)
}
func serveLogo(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "image/svg+xml")
	fmt.Fprintf(w, "%v", logo)
}
func serveFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "image/x-icon")
	fmt.Fprintf(w, "%v", favicon)
}

// ==================================================================

func RunWebServer() {
	http.Handle("/", http.RedirectHandler(CConfig.Webserver.URL+"/login", http.StatusMovedPermanently))
	http.HandleFunc("/bootstrap.min.css", serveCssBootstrap)
	http.HandleFunc("/logo.svg", serveLogo)
	http.HandleFunc("/bwinfosec_favicon.ico", serveFavicon)
	http.Handle("/index.html", http.RedirectHandler(CConfig.Webserver.URL+"/login", http.StatusMovedPermanently))
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/changepwd", changePasswordHandler)
	http.HandleFunc("/changepwdsuccess", changePasswordSuccessHandler)

	log.Info().Msg("Starting server at " + CConfig.Webserver.ListenAddress)
	if err := http.ListenAndServe(CConfig.Webserver.ListenAddress, nosurf.New(http.DefaultServeMux)); err != nil {
		log.Fatal().Stack().Err(err).Msg("RunWebServer")
	}
}

func serveIndexHtmlHandler(w http.ResponseWriter, r *http.Request) {
	ctx := make(map[string]string)
	ctx["title_prefix"] = CConfig.Webserver.PageTitlePrefix

	// fill in template parameter and execute it
	err := RConfig.Templates["index"].Execute(w, ctx)
	if err != nil {
		log.Error().Err(err).Msg("serveIndexHtmlHandler")
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

	// create context for template
	ctx := make(map[string]string)
	ctx["token"] = nosurf.Token(r)
	ctx["send_to"] = "/login"
	ctx["title_prefix"] = CConfig.Webserver.PageTitlePrefix

	if CConfig.LDAP.AuthDefaults.SeperateAdminDn {
		ctx["seperate_admin"] = "seprerate_admin"
	}
	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			log.Error().Err(err).Msg("loginHandler")
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")
		claimsAdmin := false

		if CConfig.LDAP.AuthDefaults.SeperateAdminDn {
			logintype := r.FormValue("radioUserAdmin")
			claimsAdmin = logintype == "admin"
		}

		dn := fmt.Sprintf("%s=%s,", CConfig.LDAP.AuthDefaults.IdentifyingAttribute, username)

		if claimsAdmin { // generate admin DN
			dn += CConfig.LDAP.AuthDefaults.AdminDnPostfix
		} else { // generate user DN
			dn += CConfig.LDAP.AuthDefaults.UserDnPostfix
		}

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
	err := RConfig.Templates["chpwd_success"].Execute(w, ctx)
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
func checkAdminLogin(w http.ResponseWriter, r *http.Request) error {
	cookie, err := getAuthCookie(w, r)
	if err != nil {
		return err
	}
	if cookie.Admin {
		return nil
	} else {
		err = fmt.Errorf("user is logged in but not an ADMIN")
		log.Error().Err(err).Stack().Msg("checkAdminLogin")
		return err
	}
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
func requireAdminLogin(w http.ResponseWriter, r *http.Request) error {
	cookie, err := getAuthCookie(w, r)
	if err != nil || cookie == nil {

		if err == nil && cookie == nil {
			err = fmt.Errorf("LOGIC ERROR: This code schould never be reached!!")
			return err
		}

		// Set URL to redirect to as CTX
		ctx := make(map[string]string)
		ctx["url"] = CConfig.Webserver.URL + "/login"

		// Execute Template
		err2 := RConfig.Templates["redirect"].Execute(w, ctx)
		if err2 != nil {
			log.Error().Err(err2).Msg("requireAdminLogin")
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		}
		return err
	}

	if cookie.Admin == false {
		err = fmt.Errorf("user is logged in but not ADMIN")
		log.Error().Err(err).Interface("cookie", cookie).Stack().Msg("requireAdminLogin")
		return err
	} else {
		return nil
	}
}

func settingsMenuHandler(w http.ResponseWriter, r *http.Request) {

	cookie, err := getAuthCookie(w, r)
	if err != nil || cookie == nil {
		// !! the cookie is invalid! -> force Login

		// Set URL to redirect to as CTX
		ctx := make(map[string]string)
		ctx["url"] = CConfig.Webserver.URL + "/login"
		ctx["title_prefix"] = CConfig.Webserver.PageTitlePrefix

		// Execute Template
		err = RConfig.Templates["redirect"].Execute(w, ctx)
		if err != nil {
			log.Error().Err(err).Msg("settingsMenuHandler")
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		return
	}
	admin := cookie.Admin

	if r.Method == "GET" {

		// create context for template
		ctx := make(map[string]string)
		ctx["base_url"] = CConfig.Webserver.URL
		if admin && CConfig.Webserver.ActivateAdminTools {
			ctx["admin"] = "admin"
		}

		// fill in template parameter and execute it
		err = RConfig.Templates["settings_menu"].Execute(w, ctx)
		if err != nil {
			log.Error().Err(err).Msg("settingsMenuHandler")
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
	} else {
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		log.Info().Err(fmt.Errorf("not allowed HTTP method from %s", r.RemoteAddr)).Msg("settingsMenuHandler")
		return
	}
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
		userDn := fmt.Sprintf("%s=%s,", CConfig.LDAP.AuthDefaults.IdentifyingAttribute, cookie.Username)
		if cookie.Admin { // generate admin DN
			userDn += CConfig.LDAP.AuthDefaults.AdminDnPostfix
		} else { // generate user DN
			userDn += CConfig.LDAP.AuthDefaults.UserDnPostfix
		}

		if conn != nil {
			oldPassword := r.FormValue("pwd_old")
			newPassword := r.FormValue("pwd_new")
			newPasswordConf := r.FormValue("pwd_new2")

			if newPassword != newPasswordConf {
				err_str := "Password and confirmation are not the same!"
				log.Info().Msg("changePasswordHandler: " + err_str)
				ctx["invalid"] = err_str
				err := RConfig.Templates["chpwd_form"].Execute(w, ctx)
				if err != nil {
					log.Error().Err(err).Msg("changePasswordHandler")
					http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
					return
				}
			}

			pwdModReq := ldap.NewPasswordModifyRequest(userDn, oldPassword, newPassword)

			_, err = conn.PasswordModify(pwdModReq)
			if err != nil {
				log.Error().Err(err).Msg("changePasswordHandler")
				ctx["invalid"] = err.Error()
				err = RConfig.Templates["chpwd_form"].Execute(w, ctx)
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
		err := RConfig.Templates["chpwd_form"].Execute(w, ctx)
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
func sshPubkeyHandler(w http.ResponseWriter, r *http.Request) {
	err := requireLogin(w, r)
	if err != nil {
		return
	}
	// TODO
	cookie, _ := getAuthCookie(w, r)
	conn, err := LookupLdapConn(RConfig.LdapStore, cookie.LdapConnId)
	if err != nil {
		log.Info().Str("Info", "Error finding LDAP Connection for user "+cookie.Username).Err(err).Msg("sshPubkeyHandler")
		// Set URL to redirect to as CTX
		ctx := map[string]string{"url": CConfig.Webserver.URL + "/login"}
		// Execute Template
		err = RConfig.Templates["redirect"].Execute(w, ctx)
		if err != nil {
			log.Error().Err(err).Msg("sshPubkeyHandler")
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		return
	}
	userDn := fmt.Sprintf("%s=%s,", CConfig.LDAP.AuthDefaults.IdentifyingAttribute, cookie.Username)
	if cookie.Admin { // generate admin DN
		userDn += CConfig.LDAP.AuthDefaults.AdminDnPostfix
	} else { // generate user DN
		userDn += CConfig.LDAP.AuthDefaults.UserDnPostfix
	}

	searchRequest := ldap.NewSearchRequest(
		userDn, // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=*))",           // The filter to apply
		[]string{"dn", "sshPublicKey"}, // A list attributes to retrieve
		nil,
	)
	sr, err := conn.Search(searchRequest)
	log.Info().Interface("searchResult", sr).Err(err).Msg("sshPubkeyHandler")

	fmt.Fprintf(w, "Change/Set your ssh Pub-Key!")
	for _, entry := range sr.Entries {
		fmt.Fprintf(w, "\n==========================================\n\n")
		for _, attr := range entry.Attributes {
			for _, val := range attr.Values {
				fmt.Fprintf(w, "%v: %v\n\n", attr.Name, val)
			}
		}
	}
}

func addUserHandler(w http.ResponseWriter, r *http.Request) {
	err := requireAdminLogin(w, r)
	if err != nil {
		return
	}

	fmt.Fprintf(w, "Add an User!")
}

func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	err := requireAdminLogin(w, r)
	if err != nil {
		return
	}

	fmt.Fprintf(w, "Delete an User!")
}

func resetUserPwdHandler(w http.ResponseWriter, r *http.Request) {
	err := requireAdminLogin(w, r)
	if err != nil {
		return
	}
	reset_ctx := struct {
		Token       string
		SendTo      string
		TitlePrefix string
		Users       []string
		Error       bool
		ErrorMsg    string
		BaseUrl		string
	}{
		Token:       nosurf.Token(r),
		SendTo:      "/settings/resetuserpwd",
		TitlePrefix: CConfig.Webserver.PageTitlePrefix,
		Users:       []string{},
		Error:       false,
		ErrorMsg:    "",
		BaseUrl: CConfig.Webserver.URL,
	}

	if r.Method == "GET" {
		/******************************************************************************************************
													GET
		******************************************************************************************************/
		cookie, _ := getAuthCookie(w, r)
		conn, err := LookupLdapConn(RConfig.LdapStore, cookie.LdapConnId)
		if err != nil {
			log.Info().Str("Info", "Error finding LDAP Connection for user "+cookie.Username).Err(err).Msg("resetUserPwdHandler")
			// Set URL to redirect to as CTX
			ctx := map[string]string{"url": CConfig.Webserver.URL + "/login"}
			// Execute Template
			err = RConfig.Templates["redirect"].Execute(w, ctx)
			if err != nil {
				log.Error().Err(err).Msg("resetUserPwdHandler")
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			return
		}

		// query for users
		var users = []string{}

		userSearch := ldap.NewSearchRequest(
			CConfig.LDAP.AuthDefaults.UserDnPostfix, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			"(&(objectClass=organizationalPerson))", // the filter
			[]string{"DN", CConfig.LDAP.AuthDefaults.IdentifyingAttribute},
			nil,
		)
		userSearchResult, err := conn.Search(userSearch)
		if err != nil {
			log.Info().Err(err).Msg("resetUserPwdHandler")
			// LDAP is broken we need to logout
			logout(w, r)
			// Redirect to login
			ctx := map[string]string{"url": CConfig.Webserver.URL + "/login"}
			err = RConfig.Templates["redirect"].Execute(w, ctx)
			if err != nil {
				log.Error().Err(err).Msg("resetUserPwdHandler")
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			return
		}

		for _, entry := range userSearchResult.Entries {
			for _, attr := range entry.Attributes {
				if attr.Name == CConfig.LDAP.AuthDefaults.IdentifyingAttribute {
					users = append(users, attr.Values[0])
					break
				}
			}
		}

		sort.Strings(users)
		reset_ctx.Users = users

		err = RConfig.Templates["resetpwd_form"].Execute(w, reset_ctx)
		if err != nil {
			log.Error().Err(err).Msg("resetUserPwdHandler")
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

	} else if r.Method == "POST" {
		/******************************************************************************************************
													POST
		******************************************************************************************************/
		cookie, _ := getAuthCookie(w, r)

		conn, err := LookupLdapConn(RConfig.LdapStore, cookie.LdapConnId)
		if err != nil || conn == nil {
			log.Info().Str("Info", "Error finding LDAP Connection for user "+cookie.Username).Err(err).Msg("resetUserPwdHandler")
			// Set URL to redirect to as CTX
			ctx := map[string]string{"url": CConfig.Webserver.URL + "/login"}
			// Execute Template
			err = RConfig.Templates["redirect"].Execute(w, ctx)
			if err != nil {
				log.Error().Err(err).Msg("resetUserPwdHandler")
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			return
		}

		// read POST results
		userToReset := r.FormValue("user_select")
		newPassword := r.FormValue("pwd_new")
		newPasswordConf := r.FormValue("pwd_new2")

		// query for users
		var users = make(map[string]string)

		userSearch := ldap.NewSearchRequest(
			CConfig.LDAP.AuthDefaults.UserDnPostfix, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			"(&(objectClass=organizationalPerson))", // the filter
			[]string{"DN", CConfig.LDAP.AuthDefaults.IdentifyingAttribute},
			nil,
		)

		userSearchResult, err := conn.Search(userSearch)
		if err != nil {
			// LDAP is broken we need to logout
			logout(w, r)
			// Redirect to login
			ctx := map[string]string{"url": CConfig.Webserver.URL + "/login"}
			err = RConfig.Templates["redirect"].Execute(w, ctx)
			if err != nil {
				log.Error().Err(err).Msg("resetUserPwdHandler")
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			return
		}

		for _, entry := range userSearchResult.Entries {
			for _, attr := range entry.Attributes {
				if attr.Name == CConfig.LDAP.AuthDefaults.IdentifyingAttribute {
					users[attr.Values[0]] = entry.DN
					break
				}
			}
		}

		// extract all user ids (keys)
		var uids []string = nil
		for k := range users {
			uids = append(uids, k)
		}
		sort.Strings(uids)

		// in Case something go's wrong prepare ctx
		reset_ctx.Users = uids

		// Check the Passwords
		if newPassword != newPasswordConf {
			err_str := "Password and confirmation are not the same!"
			log.Info().Msg("resetUserPwdHandler: " + err_str)
			reset_ctx.Error = true
			reset_ctx.ErrorMsg = err_str
			log.Debug().Interface("ctx", reset_ctx).Msg("Executing template")

			err := RConfig.Templates["resetpwd_form"].Execute(w, reset_ctx)
			if err != nil {
				log.Error().Err(err).Msg("resetUserPwdHandler")
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			}
			return
		}

		userDn := users[userToReset]
		if userDn == "" {
			err_str := "Unknown User!"
			log.Warn().Msg("changePasswordHandler: " + err_str)
			reset_ctx.Error = true
			reset_ctx.ErrorMsg = err_str
			err := RConfig.Templates["resetpwd_form"].Execute(w, reset_ctx)
			if err != nil {
				log.Error().Err(err).Msg("resetUserPwdHandler")
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			}
			return
		}

		// Change Password
		pwdModReq := ldap.NewPasswordModifyRequest(userDn, "", newPassword)

		_, err = conn.PasswordModify(pwdModReq)
		if err != nil {
			log.Error().Err(err).Msg("resetUserPwdHandler")
			reset_ctx.Error = true
			reset_ctx.ErrorMsg = err.Error()
			err = RConfig.Templates["resetpwd_form"].Execute(w, reset_ctx)
			if err != nil {
				log.Error().Err(err).Msg("resetUserPwdHandler")
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			return
		}

		// Password change was successful
		log.Info().Str("Affected User", userToReset).Str("Issuing User", cookie.Username).Msg("changeUserPwdHandler: successfully changed password")
		ctx := map[string]string{"url": CConfig.Webserver.URL + "/settings"}
		err = RConfig.Templates["redirect"].Execute(w, ctx)
		if err != nil {
			log.Error().Err(err).Msg("resetUserPwdHandler")
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		return

	} else {
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		log.Info().Err(fmt.Errorf("not allowed HTTP method from %s", r.RemoteAddr)).Msg("settingsMenuHandler")
		return
	}
}
