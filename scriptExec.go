package scriptExec

import (
	"io/ioutil"
	"strings"

	"golang.org/x/crypto/ssh"
	"bytes"
	"errors"
	"os"
	"fmt"
	"github.com/howeyc/gopass"
	"io"
)

func ExecCmd(conn *ssh.Client, cmd string) (string, error) {
	var (
		stdoutBuf, stderrBuf bytes.Buffer
	)
	session, err := conn.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf
	err = session.Run(cmd)
	if err != nil {
		return "", err
	}
	errorstr := stderrBuf.String()
	if errorstr != "" {
		return "", errors.New(errorstr)
	}
	return stdoutBuf.String(), nil
}

func CopyScript(session *ssh.Session, scriptFile *os.File) error{
	stats, err := scriptFile.Stat()
	if err != nil {
		return err
	}

	go func() {
		stdinWriter, _ := session.StdinPipe()
		defer stdinWriter.Close()
		fmt.Fprintln(stdinWriter, "C0775", stats.Size(), stats.Name())
		io.Copy(stdinWriter, scriptFile)
		fmt.Fprint(stdinWriter, "\x00") // transfer end with \x00
	}()
	if err := session.Run("/usr/bin/scp -t ./"); err != nil {
		return err
	}
	return nil
}

func ExecScript(conn *ssh.Client, scriptpath string, scrArg ...string) (string, error){
	session, err := conn.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	scriptFile, err := os.Open(scriptpath)
	if err != nil {
		return "", err
	}
	defer scriptFile.Close()
	if err != nil {
		return "", err
	}
	err = CopyScript(session, scriptFile)

	stats, err := scriptFile.Stat()
	cmd := "./" + stats.Name()
	for _, arg := range scrArg {
		cmd += " " + arg
	}
	fmt.Println(cmd)
	res, err := ExecCmd(conn, cmd)
	return res, err
}

func SshGetClient(login string, path string) (*ssh.ClientConfig, error) {
	var (
		pass      []byte
		sshclient *ssh.ClientConfig
		err       error
	)
	if login == "" {
		login = os.Getenv("LOGNAME")
		fmt.Println("login: ", login)
	}
	if path == "" {
		fmt.Print("Password: ")
		pass, err = gopass.GetPasswdMasked()
		if err != nil {
			return nil, err
		}
		sshclient = PassLogin(login, string(pass))
	} else {
		sshclient, err = RsaLogin(login, path)
		if err != nil {
			return nil, err
		}
	}
	return sshclient, nil
}

func ParseFile(path string) (hostslice []string, err error) {
	var hostlist []byte
	hostlist, err = ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	hostslice = strings.Split(string(hostlist), "\n")
	hostslice = PrepareSlice(hostslice)
	return hostslice, nil
}

func PrepareHost(host string) string {
	if !strings.Contains(host, ":") {
		host += ":22"
	}
	return host
}

func PrepareSlice(hostslice []string) (outslice []string) {
	for _, host := range hostslice {
		if host != "" {
			outslice = append(hostslice, PrepareHost(host))
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
