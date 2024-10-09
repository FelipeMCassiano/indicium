package db

import (
	"context"
	"database/sql"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type DataBase struct {
	conn *sql.DB
}

func (db *DataBase) Connect() error {
	conn, err := sql.Open("postgres", "postgresql://USER:PASS@localhost:5432/DB?sslmode=disable")
	if err != nil {
		return err
	}
	db.conn = conn

	return nil
}

func (db *DataBase) CreateUser(user User) error {
	tx, err := db.conn.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}

	pass, _ := bcrypt.GenerateFromPassword([]byte(user.Password), 10)

	if _, err := tx.Exec("INSERT INTO users (username, password) VALUES ($1, $2)", user.Username, string(pass)); err != nil {
		tx.Rollback()
		return err
	}

	tx.Commit()
	return nil
}

func (db *DataBase) RetrieveUser(username string) (User, error) {
	var user User
	err := db.conn.QueryRow("SELECT username, password FROM users WHERE username=$1", username).Scan(&user.Username, &user.Password)
	if err != nil {
		return User{}, nil
	}

	return user, nil
}
