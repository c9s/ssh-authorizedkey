package authorizedkey

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

type AuthorizedKeyEntry struct {
	Command string `field:"command,option"`
	// Environment       string `field:"environment,option"`
	Environment       map[string]string `field:"environment,option"`
	CertAuthority     bool              `field:"cert-authority,option"`
	Principals        string            `field:"principlas,option"`
	Pty               bool              `field:"pty,option"`
	PortForwarding    bool              `field:"port-forwarding,option"`
	X11Forwarding     bool              `field:"x11-forwarding,option"`
	UserRC            bool              `field:"user-rc,option"`
	Restrict          bool              `field:"restrict,option"`
	NoPortForwarding  bool              `field:"no-port-forwarding,option"`
	NoAgentForwarding bool              `field:"no-agent-forwarding,option"`
	NoPty             bool              `field:"no-pty,option"`
	NoX11Forwarding   bool              `field:"no-x11-forwarding,option"`
	NoUserRC          bool              `field:"no-user-rc,option"`
	Tunnel            string            `field:"tunnel,option"`
	KeyType           string            `field:",keytype"`
	Key               string            `field:",key"`
	Comment           string            `field:",comment"`
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
					out.options = append(out.options, args[0]+"="+strconv.Quote(strings.Join(pairs, " ")))

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
	return fmt.Sprintf("%s %s %s %s", strings.Join(out.options, ","), out.keyType, out.key, out.comment)
}
