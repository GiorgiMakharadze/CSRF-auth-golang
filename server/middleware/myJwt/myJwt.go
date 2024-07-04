package myJwt

import (
	"crypto/rsa"
	_ "errors"
	_ "log"
	"os"
	"time"

	"github.com/GiorgiMakharadze/CSRF-auth-golang/db"
	"github.com/GiorgiMakharadze/CSRF-auth-golang/db/models"
	jwt "github.com/dgrijalva/jwt-go"
)

const(
	privKeyPath = "keys/app.rsa"
	pubKeyPath = "keys/app.rsa.pub"
)

var (
	signKey   *rsa.PrivateKey
	verifyKey *rsa.PublicKey
)

func InitJWT() error{
	signBytes, err := os.ReadFile(privKeyPath)
	if err != nil{
		return err
	}

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return err
	}

	verifyBytes,err := os.ReadFile(pubKeyPath)
	if err != nil {
		return err
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return err
	}
	return nil
}

func CreateNewTokens(uuid, role string)(authTokenString, refreshTokenString, csrfSecret string, err error) {

	csrfSecret, err = models.GenerateCSRFSecret()
	if err != nil{
		return
	} 
	refreshTokenString, err = createRefreshTokenString(uuid, role, csrfSecret)

authTokenString, err = createAuthTokenString(uuid, role, csrfSecret)	
if err != nil{
	return
}
return
}

func CheckAndRefreshTokens()() {

}

func createAuthTokenString(uuid, role, csrfSecret string)(authTokenString string, err error) {
	authTokenExp := time.Now().Add(models.AuthTokenValidTime).Unix()
	authClaims := models.TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Subject: uuid,
			ExpiresAt: authTokenExp,
		},
		Role: role,
		Csrf: csrfSecret,
	}
	authJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), authClaims)
	authTokenString, err = authJwt.SignedString(signKey)
	return
}

func createRefreshTokenString(uuid,role, csrfString string)(refreshTokenString string, err error){
	refreshTokenExp := time.Now().Add(models.RefreshTokenValidTime).Unix()
	refreshJti, err := db.StoreRefreshToken()
	if err != nil{
		return
	}
	refreshClaims := models.TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Id: refreshJti,
			Subject: uuid,
			ExpiresAt: refreshTokenExp,
		},
		Role: role,
		Csrf: csrfString,

	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)
	refreshTokenString, err = refreshJwt.SignedString(signKey)
	return
}
func updateRefreshTokenExp()() {
	
}

func updateAuthTokenString()() {
}

func RevokeRefreshToken() error {
}

func updateRefreshTokenCsrf()(){

}

func GrabUUID()(){

}