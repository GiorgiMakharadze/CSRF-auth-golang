package middleware

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/GiorgiMakharadze/CSRF-auth-golang/db"
	"github.com/GiorgiMakharadze/CSRF-auth-golang/server/middleware/myJwt"
	"github.com/GiorgiMakharadze/CSRF-auth-golang/server/templates"
	"github.com/justinas/alice"
)

func NewHandler() http.Handler {
	return alice.New(recoverHandler, authHandler).ThenFunc(logicHandler)

}

func recoverHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Panicf("Recovered! Panic:%+v,", err)
				http.Error(w, http.StatusText(500), 500)
			}
		}()
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func authHandler(next http.Handler) http.Handler {
    fn := func(w http.ResponseWriter, r *http.Request) {
        log.Println("Auth handler triggered for path:", r.URL.Path)

        switch r.URL.Path {
        case "/restricted", "/logout", "/deleteUser":
            log.Println("In auth restricted section")

            AuthCookie, authErr := r.Cookie("AuthToken")
            if authErr == http.ErrNoCookie {
                log.Println("Unauthorized attempt! No auth cookie")
                nullifyTokenCookies(&w, r)
                http.Redirect(w, r, "/login", http.StatusFound)
                http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
                return
            } else if authErr != nil {
                log.Panicf("panic: %+v", authErr)
                nullifyTokenCookies(&w, r)
                http.Error(w, http.StatusText(500), 500)
                return
            }

            RefreshCookie, refreshErr := r.Cookie("RefreshToken")
            if refreshErr == http.ErrNoCookie {
                log.Println("Unauthorized attempt! No refresh cookie")
                nullifyTokenCookies(&w, r)
                http.Redirect(w, r, "/login", http.StatusFound)
                return
            } else if refreshErr != nil {
                log.Panicf("panic: %+v", refreshErr)
                nullifyTokenCookies(&w, r)
                http.Error(w, http.StatusText(500), 500)
                return
            }

            requestCsrfToken := grabCsrfFromReq(r)
            log.Println("CSRF Token from request:", requestCsrfToken)

            authTokenString, refreshTokenString, csrfSecret, err := myJwt.CheckAndRefreshTokens(AuthCookie.Value, RefreshCookie.Value, requestCsrfToken)
            if err != nil {
                if err.Error() == "Unauthorized" {
                    log.Println("Unauthorized attempt! JWT's not valid!")
                    nullifyTokenCookies(&w, r)
                    http.Redirect(w, r, "/login", http.StatusFound)
                    http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
                    return
                } else {
                    log.Println("Error validating tokens:", err)
                    log.Panicf("panic: %+v", err)
                    nullifyTokenCookies(&w, r)
                    http.Error(w, http.StatusText(500), 500)
                    return
                }
            }
            log.Println("Successfully recreated JWTs")

            w.Header().Set("Access-Control-Allow-Origin", "*")

            setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
            w.Header().Set("X-CSRF-Token", csrfSecret)

        default:
        }

        next.ServeHTTP(w, r)
    }

    return http.HandlerFunc(fn)
}

func logicHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/restricted":
		csrfSecret := grabCsrfFromReq(r)
		AuthCookie, err := r.Cookie("AuthToken")
        if err != nil {
            http.Redirect(w, r, "/login", http.StatusFound)
            return
        }

        uuid, err := myJwt.GrabUUID(AuthCookie.Value)
        if err != nil {
            log.Panicf("panic: %+v", err)
            http.Error(w, http.StatusText(500), 500)
            return
        }

        user, err := db.FetchUserById(uuid)
        if err != nil {
            log.Panicf("panic: %+v", err)
            http.Error(w, http.StatusText(500), 500)
            return
        }

		templates.RenderTemplate(w, "restricted", &templates.RestrictedPage{CsrfSecret: csrfSecret, SecretMessage: uuid, Username: user.Username})



	case "/login":
		switch r.Method {
		case "GET":
			templates.RenderTemplate(w, "login", &templates.LoginPage{BAlertUser: false, AlertMsg: ""})

		case "POST":
			r.ParseForm()
			log.Println(r.Form)

			user, uuid, loginErr := db.LogUserIn(strings.Join(r.Form["username"], ""), strings.Join(r.Form["password"], ""))
			log.Println(user, uuid, loginErr)
			if loginErr != nil {
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				authTokenString, refreshTokenString, csrfSecret, err := myJwt.CreateNewTokens(uuid, user.Role)
				if err != nil {
					http.Error(w, http.StatusText(500), 500)
				}

				setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
				w.Header().Set("X-CSRF-Token", csrfSecret)

				w.WriteHeader(http.StatusOK)
			}

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/register":
		switch r.Method {
		case "GET":
			templates.RenderTemplate(w, "register", &templates.RegisterPage{BAlertUser: false, AlertMsg: ""})

		case "POST":
			r.ParseForm()
			log.Println(r.Form)

			_, uuid, err := db.FetchUserByUsername(strings.Join(r.Form["username"], ""))
			if err == nil {
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				role := "user"
				uuid, err = db.StoreUser(strings.Join(r.Form["username"], ""), strings.Join(r.Form["password"], ""), role)
				if err != nil {
					http.Error(w, http.StatusText(500), 500)
				}
				log.Println("uuid: " + uuid)

				authTokenString, refreshTokenString, csrfSecret, err := myJwt.CreateNewTokens(uuid, role)
				if err != nil {
					http.Error(w, http.StatusText(500), 500)
				}

				setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
				w.Header().Set("X-CSRF-Token", csrfSecret)

				w.WriteHeader(http.StatusOK)
			}

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/logout":
		nullifyTokenCookies(&w, r)
		http.Redirect(w, r, "/login", http.StatusFound)

	case "/deleteUser":
		log.Println("Deleting user")

		AuthCookie, authErr := r.Cookie("AuthToken")
		if authErr == http.ErrNoCookie {
			log.Println("Unauthorized attempt! No auth cookie")
			nullifyTokenCookies(&w, r)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		} else if authErr != nil {
			log.Panicf("panic: %+v", authErr)
			nullifyTokenCookies(&w, r)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		uuid, uuidErr := myJwt.GrabUUID(AuthCookie.Value)
		if uuidErr != nil {
			log.Panicf("panic: %+v", uuidErr)
			nullifyTokenCookies(&w, r)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		db.DeleteUser(uuid)
		nullifyTokenCookies(&w, r)
		http.Redirect(w, r, "/register", http.StatusFound)

	default:
		w.WriteHeader(http.StatusOK)
	}
}

func nullifyTokenCookies(w *http.ResponseWriter, r *http.Request) {
	authCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}

	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}

	http.SetCookie(*w, &refreshCookie)

	RefreshCookie, refreshErr := r.Cookie("RefreshToken")
	if refreshErr == http.ErrNoCookie {
		return
	} else if refreshErr != nil {
		log.Panicf("panic: %+v", refreshErr)
		http.Error(*w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	myJwt.RevokeRefreshToken(RefreshCookie.Value)
}

func setAuthAndRefreshCookies(w *http.ResponseWriter, authTokenString string, refreshTokenString string) {
	authCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    authTokenString,
		HttpOnly: true,
	}

	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    refreshTokenString,
		HttpOnly: true,
	}

	http.SetCookie(*w, &refreshCookie)
}

func grabCsrfFromReq(r *http.Request) string {
	csrfFromFrom := r.FormValue("X-CSRF-Token")

	if csrfFromFrom != "" {
		return csrfFromFrom
	} else {
		return r.Header.Get("X-CSRF-Token")
	}
}

