package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/FelipeMCassiano/indicium/db"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

var database *db.DataBase

func main() {
	router := http.NewServeMux()

	conn := new(db.DataBase)
	if err := conn.Connect(); err != nil {
		log.Fatal(err)
	}

	database = conn

	router.HandleFunc("POST /createUser", CreateUserHandler)
	router.HandleFunc("POST /login", LoginHandler)
	protectedFunc := http.HandlerFunc(ProtectedHandler)
	router.Handle("GET /protected", cookieMiddleware(protectedFunc))
	router.HandleFunc("DELETE /logout", LogoutHandler)

	server := http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	fmt.Println("running at 8080 port")

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

var secretKey = []byte("secret-key")

func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var u db.User
	json.NewDecoder(r.Body).Decode(&u)

	if err := database.CreateUser(u); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	return
}

func setCookie(token string) http.Cookie {
	cookie := http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}

	return cookie
}

func cookieMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("token")
		if err != nil {
			switch {
			case errors.Is(err, http.ErrNoCookie):
				http.Error(w, "cookie not found", http.StatusBadRequest)
				return

			default:
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
		}

		err = verifyToken(cookie.Value)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "Invalid token")
			return
		}

		h.ServeHTTP(w, r)
	})
}

func CreateToken(username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
		"iat":      time.Now().Unix(),
	})

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func verifyToken(tokenString string) error {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		return err
	}

	if !token.Valid {
		return fmt.Errorf("invalid token")
	}

	return nil
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var u db.User
	json.NewDecoder(r.Body).Decode(&u)

	fmt.Printf("The user request value %v\n", u)

	user, err := database.RetrieveUser(u.Username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	passHash, _ := bcrypt.GenerateFromPassword([]byte(u.Password), 10)

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), passHash)

	if err != nil && u.Username == user.Username {
		tokenString, err := CreateToken(user.Username)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "No username found")
			return

		}

		cookie := setCookie(tokenString)
		http.SetCookie(w, &cookie)

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "cookie set!")
		return
	}

	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprint(w, "Invalid credentials")
}

func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	fmt.Fprint(w, "welcome to the protected area")
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	cookie, err := r.Cookie("token")
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	cookie.MaxAge = -1

	http.SetCookie(w, cookie)
	fmt.Fprint(w, "logout successfully")
	return
}
