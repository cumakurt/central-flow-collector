package ldapauth

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"
)

func TestLDAPAuthenticateAndGroupMap(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	go func() {
		c, _ := ln.Accept()
		defer c.Close()
		r := bufio.NewReader(c)
		for n := 0; n < 3; n++ {
			p, e := ReadPacket(r)
			if e != nil {
				return
			}
			id, tag, _ := DecodeMessageID(p)
			switch tag {
			case 0x60:
				c.Write(EncodeBindResult(id, 0))
			case 0x63:
				c.Write(EncodeSearchEntry(id, "CN=alice,DC=x", "memberOf", []string{"CN=SOC,DC=x"}))
				c.Write(EncodeSearchDone(id, 0))
			}
		}
	}()
	m, e := New(Config{URL: "ldap://" + ln.Addr().String(), AllowInsecure: true, BindDN: "CN=svc", BindPassword: "x", BaseDN: "DC=x", GroupRoleMap: "CN=SOC,DC=x=analyst"})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	id, e := m.Authenticate(ctx, "alice", "pw")
	if e != nil {
		t.Fatal(e)
	}
	if id.Role != "analyst" {
		t.Fatalf("%+v", id)
	}
}
