package scriptExec

import (
	"io/ioutil"
	"strings"

	"golang.org/x/crypto/ssh"
	"bytes"
	"errors"
)

func ExecScript(s *ssh.Session, cmd string, arguments string) (string, error) {
	var stdoutBuf, stderrBuf bytes.Buffer
	s.Stdout = &stdoutBuf
	s.Stderr = &stderrBuf
	err := s.Run("bash <<EOF " + arguments + "\n" + cmd + "\nEOF")
	error := stderrBuf.String()
	if err != nil {
		return "", err
	}
	if error != "" {
		return "", errors.New(stderrBuf.String())
	}
	return stdoutBuf.String(), nil
}

func ParseFile(path string) (hostslice []string, err error) {
	var hostlist []byte
	hostlist, err = ioutil.ReadFile(path)
	if err != nil {
		return hostslice, err
	}
	hostslice = strings.Split(string(hostlist), "\n")
	hostslice = PrepareSlice(hostslice)
	return hostslice, nil
}

func PrepareSlice(hostslice []string) (outslice []string) {
	for _, host := range hostslice {
		if host != "" {
			if strings.Contains(host, ":") {
				outslice = append(hostslice, host)
			} else {
				outslice = append(hostslice, host+":22")
			}
		}
	}
	return
}

func PassLogin(login string, pass string) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            login,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
}

func RsaLogin(login string, path string) (*ssh.ClientConfig, error) {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(buf)
	if err != nil {
		return nil, err
	}
	return &ssh.ClientConfig{
		User:            login,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}, nil
}
