package authorizedkey

import "github.com/stretchr/testify/assert"
import "testing"

func TestEncode(t *testing.T) {
	entry := AuthorizedKeyEntry{
		KeyType:          "ssh-rsa",
		Key:              `AAAAB3NzaC1yc2EAAAABIwAAAQEA5NfeDCmVCzQzlBPdom6OOj6A9reyPS8+176+M68WKWfmHjJJ0we3jlz3I438oq4Y8l5liunrPj4emrNSMj3nzB/FG/1YItHaMwqRIIUmFYdaEpHZkrBfJ2rsVmcfLX6GBqJMtyZpIvztCY7OH+D+qn9l3ZZDDKVp0Cal4RO6Q15T2zEb4utq4epQSm58zL+hYyG0j98sCJPmBxkRLb18UKQqnRbfaf8i8Iwy2fhK55hwPbGOfXlUx1z5thtZFRrsgAYrypBBuZYMuny/eCBAO2wPyt3bDM3ZnBEf76ODHhQvIyK99YEdiiLHIWVnrnaIQ3f3Q1zMY34E4ErKwwUlEw==`,
		Environment:      map[string]string{"foo": "bar"},
		Command:          "env >> /home/git/ssh-log",
		NoPty:            true,
		NoPortForwarding: true,
	}
	t.Logf("%s", entry.String())
	assert.Equal(t, `command="env >> /home/git/ssh-log",environment="foo=\"bar\"",cert-authority,pty,port-forwarding,x11-forwarding,user-rc,restrict,no-port-forwarding,no-agent-forwarding,no-pty,no-x11-forwarding,no-user-rc ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA5NfeDCmVCzQzlBPdom6OOj6A9reyPS8+176+M68WKWfmHjJJ0we3jlz3I438oq4Y8l5liunrPj4emrNSMj3nzB/FG/1YItHaMwqRIIUmFYdaEpHZkrBfJ2rsVmcfLX6GBqJMtyZpIvztCY7OH+D+qn9l3ZZDDKVp0Cal4RO6Q15T2zEb4utq4epQSm58zL+hYyG0j98sCJPmBxkRLb18UKQqnRbfaf8i8Iwy2fhK55hwPbGOfXlUx1z5thtZFRrsgAYrypBBuZYMuny/eCBAO2wPyt3bDM3ZnBEf76ODHhQvIyK99YEdiiLHIWVnrnaIQ3f3Q1zMY34E4ErKwwUlEw==`, entry.String())
}
