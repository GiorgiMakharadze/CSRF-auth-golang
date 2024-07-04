package db

import (
	"errors"
	_ "log"

	"github.com/GiorgiMakharadze/CSRF-auth-golang/db/models"
	_ "golang.org/x/crypto/bcrypt"
)

var users = map[string]models.User{}

func InitDB(){

}

func StoreUser(username, password, role string)(uuid string, err error){

}

func DeleteUser() {

}

func FetchUserById()() {

}

func FetchUserByUsername(username string)(models.User, string, error) {
  for k, v :=	range users{
		if v.Username == username{
			return v,k,nil
		}
	}
	return models.User{}, "", errors.New("User not found that matches te given username")
}

func StoreRefreshToken()(){

}

func DeleteRefreshToken(){

}

func CheckAndRefreshToken() bool {

}

func LogUserIn()() {

}

func generateBcryptHash()() {

}

func checkPasswordAgainstHash() error {}