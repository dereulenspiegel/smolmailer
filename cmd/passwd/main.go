package main

import (
	"fmt"
	"os"

	"github.com/dereulenspiegel/smolmailer"
)

func main() {
	if len(os.Args) != 2 {
		panic(fmt.Errorf("not enough arguments, please specify the password"))
	}

	encodedPasswd := smolmailer.MustEncodePassword(os.Args[1])
	fmt.Print(encodedPasswd)
}
