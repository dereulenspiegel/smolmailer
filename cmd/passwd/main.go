package main

import (
	"fmt"
	"os"

	"github.com/dereulenspiegel/smolmailer/internal/users"
)

func main() {
	if len(os.Args) != 2 {
		panic(fmt.Errorf("not enough arguments, please specify the password"))
	}

	encodedPasswd := users.MustEncodePassword(os.Args[1])
	fmt.Print(encodedPasswd)
}
