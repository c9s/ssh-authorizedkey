Authorized Key Encoder
======================

This package provides the funtionality for encoding the the authorized key entry:

```
entry := authorizedkey.AuthorizedKeyEntry{
    KeyType:          "ssh-rsa",
    Key:              `AAAA.....`,
    Environment:      map[string]string{"foo": "bar"},
    Command:          "gitolite-shell",
    NoPty:            true,
    NoPortForwarding: true,
}
fmt.Println(entry.String())
```


LICENSE
=======

MIT License

AUTHOR
=======

Yo-An Lin <yoanlin93@gmail.com>

