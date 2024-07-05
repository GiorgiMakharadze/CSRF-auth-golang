package myJwt

import (
	"crypto/rsa"
	"errors"
	"log"
	"os"
	"time"

	"github.com/GiorgiMakharadze/CSRF-auth-golang/db"
	"github.com/GiorgiMakharadze/CSRF-auth-golang/db/models"
	jwt "github.com/dgrijalva/jwt-go"
)

const (
	privKeyPath = "keys/app.rsa"
	pubKeyPath  = "keys/app.rsa.pub"
)

var (
	signKey   *rsa.PrivateKey
	verifyKey *rsa.PublicKey
)

func InitJWT() error {
    signBytes, err := os.ReadFile(privKeyPath)
    if err != nil {
        log.Fatalf("Failed to read private key: %v", err)
    }

    signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
    if err != nil {
        log.Fatalf("Failed to parse private key: %v", err)
    }

    verifyBytes, err := os.ReadFile(pubKeyPath)
    if err != nil {
        log.Fatalf("Failed to read public key: %v", err)
    }

    verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
    if err != nil {
        log.Fatalf("Failed to parse public key: %v", err)
    }

    log.Println("JWT initialization successful")
    return nil
}
func CreateNewTokens(uuid string, role string) (authTokenString, refreshTokenString, csrfSecret string, err error) {

	csrfSecret, err = models.GenerateCSRFSecret()
	if err != nil {
		return
	}

	refreshTokenString, err = createRefreshTokenString(uuid, role, csrfSecret)
	if err != nil {
		return
	}

	authTokenString, err = createAuthTokenString(uuid, role, csrfSecret)
	if err != nil {
		return
	}

	return
}

func CheckAndRefreshTokens(oldAuthTokenString string, oldRefreshTokenString string, oldCsrfSecret string) (newAuthTokenString, newRefreshTokenString, newCsrfSecret string, err error) {
    if oldCsrfSecret == "" {
        log.Println("No CSRF token!")
        err = errors.New("Unauthorized")
        return
    }

    authToken, err := jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
        return verifyKey, nil
    })
    if err != nil {
        log.Println("Error parsing auth token:", err)
        return
    }
    authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
    if !ok {
        log.Println("Error reading auth token claims")
        return
    }
    if oldCsrfSecret != authTokenClaims.Csrf {
        log.Println("CSRF token doesn't match jwt!")
        err = errors.New("Unauthorized")
        return
    }

    if authToken.Valid {
        log.Println("Auth token is valid")

        newCsrfSecret = authTokenClaims.Csrf

        newRefreshTokenString, err = updateRefreshTokenExp(oldRefreshTokenString)
        newAuthTokenString = oldAuthTokenString
        return
    } else if ve, ok := err.(*jwt.ValidationError); ok {
        log.Println("Auth token is not valid")
        if ve.Errors&(jwt.ValidationErrorExpired) != 0 {
            log.Println("Auth token is expired")

            newAuthTokenString, newCsrfSecret, err = updateAuthTokenString(oldRefreshTokenString, oldAuthTokenString)
            if err != nil {
                return
            }

            newRefreshTokenString, err = updateRefreshTokenExp(oldRefreshTokenString)
            if err != nil {
                return
            }

            newRefreshTokenString, err = updateRefreshTokenCsrf(newRefreshTokenString, newCsrfSecret)
            return
        } else {
            log.Println("Error in auth token:", err)
            err = errors.New("error in auth token")
            return
        }
    } else {
        log.Println("Error in auth token:", err)
        err = errors.New("error in auth token")
        return
    }
    return
}

func createAuthTokenString(uuid string, role string, csrfSecret string) (authTokenString string, err error) {
    authTokenExp := time.Now().Add(models.AuthTokenValidTime).Unix()
    authClaims := models.TokenClaims{
        StandardClaims: jwt.StandardClaims{
            Subject:   uuid,
            ExpiresAt: authTokenExp,
        },
        Role: role,
        Csrf: csrfSecret,
    }

    authJwt := jwt.NewWithClaims(jwt.SigningMethodRS256, authClaims)

    authTokenString, err = authJwt.SignedString(signKey)
    if err != nil {
        log.Printf("Error signing auth token: %v", err)
    }
    return
}

func createRefreshTokenString(uuid string, role string, csrfString string) (refreshTokenString string, err error) {
    refreshTokenExp := time.Now().Add(models.RefreshTokenValidTime).Unix()
    refreshJti, err := db.StoreRefreshToken()
    if err != nil {
        return
    }

    refreshClaims := models.TokenClaims{
        StandardClaims: jwt.StandardClaims{
            Id:        refreshJti,
            Subject:   uuid,
            ExpiresAt: refreshTokenExp,
        },
        Role: role,
        Csrf: csrfString,
    }

    refreshJwt := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims)

    refreshTokenString, err = refreshJwt.SignedString(signKey)
    if err != nil {
        log.Printf("Error signing refresh token: %v", err)
    }
    return
}

func updateRefreshTokenExp(oldRefreshTokenString string) (newRefreshTokenString string, err error) {
	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	oldRefreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		return
	}

	refreshTokenExp := time.Now().Add(models.RefreshTokenValidTime).Unix()

	refreshClaims := models.TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        oldRefreshTokenClaims.StandardClaims.Id, // jti
			Subject:   oldRefreshTokenClaims.StandardClaims.Subject,
			ExpiresAt: refreshTokenExp,
		},
		Role: oldRefreshTokenClaims.Role,
		Csrf: oldRefreshTokenClaims.Csrf,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)

	newRefreshTokenString, err = refreshJwt.SignedString(signKey)
	return
}

func updateAuthTokenString(refreshTokenString string, oldAuthTokenString string) (newAuthTokenString, csrfSecret string, err error) {
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	refreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		err = errors.New("error reading jwt claims")
		return
	}

	if db.CheckRefreshToken(refreshTokenClaims.StandardClaims.Id) {

		if refreshToken.Valid {

			authToken, _ := jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
				return verifyKey, nil
			})

			oldAuthTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
			if !ok {
				err = errors.New("error reading jwt claims")
				return
			}

			csrfSecret, err = models.GenerateCSRFSecret()
			if err != nil {
				return
			}

			newAuthTokenString, err = createAuthTokenString(oldAuthTokenClaims.StandardClaims.Subject, oldAuthTokenClaims.Role, csrfSecret)

			return
		} else {
			log.Println("Refresh token has expired!")

			db.DeleteRefreshToken(refreshTokenClaims.StandardClaims.Id)

			err = errors.New("Unauthorized")
			return
		}
	} else {
		log.Println("Refresh token has been revoked!")

		err = errors.New("Unauthorized")
		return
	}
}

func RevokeRefreshToken(refreshTokenString string) error {
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil {
		return errors.New("could not parse refresh token with claims")
	}

	refreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		return errors.New("could not read refresh token claims")
	}

	db.DeleteRefreshToken(refreshTokenClaims.StandardClaims.Id)

	return nil
}

func updateRefreshTokenCsrf(oldRefreshTokenString string, newCsrfString string) (newRefreshTokenString string, err error) {
	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	oldRefreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		return
	}

	refreshClaims := models.TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        oldRefreshTokenClaims.StandardClaims.Id,
			Subject:   oldRefreshTokenClaims.StandardClaims.Subject,
			ExpiresAt: oldRefreshTokenClaims.StandardClaims.ExpiresAt,
		},
		Role: oldRefreshTokenClaims.Role,
		Csrf: newCsrfString,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)

	newRefreshTokenString, err = refreshJwt.SignedString(signKey)
	return
}

func GrabUUID(authTokenString string) (string, error) {
	authToken, _ := jwt.ParseWithClaims(authTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return "", errors.New("error fetching claims")
	})
	authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
	if !ok {
		return "", errors.New("error fetching claims")
	}

	return authTokenClaims.StandardClaims.Subject, nil
}

