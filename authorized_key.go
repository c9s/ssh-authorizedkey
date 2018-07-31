package authorizedkey

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

type AuthorizedKeyEntry struct {
	Command string `field:"command,option" json:"command"`
	// Environment       string `field:"environment,option"`
	Environment       map[string]string `field:"environment,option" json:"environment"`
	CertAuthority     bool              `field:"cert-authority,option" json:"certAuthority"`
	Principals        string            `field:"principlas,option" json:"principals"`
	Pty               bool              `field:"pty,option" json:"pty"`
	PortForwarding    bool              `field:"port-forwarding,option" json:"portForwarding"`
	X11Forwarding     bool              `field:"x11-forwarding,option" json:"x11Forwarding"`
	UserRC            bool              `field:"user-rc,option" json:"userRC"`
	Restrict          bool              `field:"restrict,option" json:"restrict"`
	NoPortForwarding  bool              `field:"no-port-forwarding,option" json:"noPortForwarding"`
	NoAgentForwarding bool              `field:"no-agent-forwarding,option" json:"noAgentForwarding"`
	NoPty             bool              `field:"no-pty,option" json:"noPty"`
	NoX11Forwarding   bool              `field:"no-x11-forwarding,option" json:"noX11Forwarding"`
	NoUserRC          bool              `field:"no-user-rc,option" json:"noUserRC"`
	Tunnel            string            `field:"tunnel,option" json:"tunnel"`
	KeyType           string            `field:",keytype" json:"keyType"`
	Key               string            `field:",key" json:"key"`
	Comment           string            `field:",comment" json:"comment"`

	FingerprintSHA256 string `field:"-" json:"fingerprintSHA256"`
}

func (e AuthorizedKeyEntry) PublicKey() (out ssh.PublicKey, comment string, options []string, rest []byte, err error) {
	return ssh.ParseAuthorizedKey(e.PublicKeyBytes())
}

func (e AuthorizedKeyEntry) PublicKeyBytes() []byte {
	return []byte(e.PublicKeyString())
}

func (e AuthorizedKeyEntry) PublicKeyString() string {
	return e.KeyType + " " + e.Key
}

func (e AuthorizedKeyEntry) String() string {
	return ReflectEncode(e)
}

func ReflectEncode(entry interface{}) string {
	out := struct {
		options []string
		key     string
		keyType string
		comment string
	}{}
	reftype := reflect.TypeOf(entry)
	refval := reflect.ValueOf(entry)
	for i := 0; i < reftype.NumField(); i++ {
		tfield := reftype.Field(i)
		vfield := refval.Field(i)

		tag := tfield.Tag.Get("field")
		args := strings.Split(tag, ",")
		if len(args[0]) == 0 {
			args[0] = tfield.Name
		}

		if args[0] == "-" {
			continue
		}

		for _, a := range args[1:] {
			switch a {
			case "keytype":
				out.keyType = refval.Field(i).String()
			case "key":
				out.key = refval.Field(i).String()
			case "comment":
				out.comment = refval.Field(i).String()
			case "option":
				switch tfield.Type.Kind() {

				case reflect.Map:
					var pairs []string
					for _, key := range vfield.MapKeys() {
						var val = vfield.MapIndex(key)
						switch val.Kind() {
						case reflect.String:
							pairs = append(pairs, key.String()+"="+strconv.Quote(val.String()))
						case reflect.Int:
							pairs = append(pairs, key.String()+"="+strconv.Quote(strconv.FormatInt(val.Int(), 10)))
						case reflect.Bool:
							pairs = append(pairs, key.String()+"="+strconv.Quote(strconv.FormatBool(val.Bool())))
						}
					}
					if len(pairs) > 0 {
						out.options = append(out.options, args[0]+"="+strconv.Quote(strings.Join(pairs, " ")))
					}

				case reflect.String:
					if len(vfield.String()) > 0 {
						out.options = append(out.options, args[0]+"="+strconv.Quote(vfield.String()))
					}
				case reflect.Bool:
					out.options = append(out.options, args[0])
				}
			}
		}
	}
	return strings.TrimSpace(fmt.Sprintf("%s %s %s %s", strings.Join(out.options, ","), out.keyType, out.key, out.comment))
}
