Authorized Key Encoder
======================

This package provides the funtionality for encoding the the authorized key entry:

```go
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

The code above generates:

```
command="env",environment="foo=\"bar\"",cert-authority,pty,port-forwarding,x11-forwarding,user-rc,restrict,no-port-forwarding,no-agent-forwarding,no-pty,no-x11-forwarding,no-user-rc ssh-rsa AAAA..... c9s@mac
```


LICENSE
=======

MIT License

AUTHOR
=======

Yo-An Lin <yoanlin93@gmail.com>

