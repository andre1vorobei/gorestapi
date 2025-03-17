package model

import (
	"github.com/asaskevich/govalidator"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID                int
	Email             string `valid:"email" json:"email"`
	UserName          string `valid:"alphanum" json:"username"`
	Password          string `json:"password"`
	EncryptedPassword string
}

func (u *User) Validate() error {
	_, err := govalidator.ValidateStruct(u)

	if err != nil {
		return err
	}

	return nil
}

func (u *User) BeforeCreate() error {
	if len(u.Password) > 0 {
		enc, err := encryptStrin(u.Password)
		if err != nil {
			return err
		}

		u.EncryptedPassword = enc
	}
	return nil
}

func encryptStrin(str string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(str), bcrypt.MinCost)
	if err != nil {
		return "", err
	}
	return string(b), err
}
