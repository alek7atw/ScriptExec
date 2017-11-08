package ScriptExec

import (
	"io/ioutil"
	"strings"
	"os"
	"fmt"

	"github.com/howeyc/gopass"
	"golang.org/x/crypto/ssh"
)

func ExecScript(s *ssh.Session, cmd string) ([]byte, error) {
	out, err := s.CombinedOutput("bash <<EOF\n" + cmd + "\nEOF")
	if err != nil {
		return out, err
	}
	return out, nil
}

func ParseFile(path string) (hostslice []string, err error) {
	var hostlist []byte
	hostlist, err = ioutil.ReadFile(path)
	if err != nil {
		return hostslice, err
	}
	for _, host := range strings.Split(string(hostlist), "\n") {
		if host != "" {
			if strings.Contains(host, ":") {
				hostslice = append(hostslice, host)
			} else {
				hostslice = append(hostslice, host+":22")
			}
		}
	}
	return hostslice, nil
}

func PassLogin(login string, pass string) *ssh.ClientConfig {
	if login == "" {
		login = os.Getenv("LOGNAME")
	}
	return &ssh.ClientConfig{
		User:            login,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
}

func RsaLogin(login string, path string) (*ssh.ClientConfig, error) {
	if login == "" {
		login = os.Getenv("LOGNAME")
	}
	if path == "" {
		path = os.Getenv("HOME") + "/.ssh/id_rsa"
	}
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(buf)
	if err != nil {
		return nil, err
	}
	return &ssh.ClientConfig{
		User: login,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}, nil
}

func AskPassWord() (string, error) {
	fmt.Print("Password: ")
	pass, err := (gopass.GetPasswdMasked())
	if err != nil {
		return "", err
	}
	return string(pass), nil
}
