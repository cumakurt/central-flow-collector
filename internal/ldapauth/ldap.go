package ldapauth

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	URL            string
	BindDN         string
	BindPassword   string
	BaseDN         string
	UserAttribute  string
	UserDNTemplate string
	GroupAttribute string
	GroupRoleMap   string
	DefaultRole    string
	AllowInsecure  bool
	TLSConfig      *tls.Config
}
type Identity struct {
	Username, DN, Role string
	Groups             []string
}
type Manager struct {
	cfg     Config
	roleMap map[string]string
}

func New(cfg Config) (*Manager, error) {
	u, e := url.Parse(cfg.URL)
	if e != nil {
		return nil, e
	}
	if u.Scheme != "ldaps" && u.Scheme != "ldap" {
		return nil, errors.New("LDAP URL must use ldap:// or ldaps://")
	}
	if u.Scheme == "ldap" && !cfg.AllowInsecure {
		return nil, errors.New("plaintext LDAP requires allow_insecure=true; use ldaps:// in production")
	}
	if cfg.UserAttribute == "" {
		cfg.UserAttribute = "sAMAccountName"
	}
	if cfg.GroupAttribute == "" {
		cfg.GroupAttribute = "memberOf"
	}
	if cfg.DefaultRole == "" {
		cfg.DefaultRole = "read_only"
	}
	cfg.DefaultRole = normalizeRole(cfg.DefaultRole)
	if cfg.UserDNTemplate == "" && cfg.BaseDN == "" {
		return nil, errors.New("LDAP base_dn or user_dn_template required")
	}
	return &Manager{cfg: cfg, roleMap: parseMap(cfg.GroupRoleMap)}, nil
}
func parseMap(s string) map[string]string {
	m := map[string]string{}
	for _, x := range strings.Split(s, ";") {
		x = strings.TrimSpace(x)
		i := strings.LastIndex(x, "=")
		if i > 0 && i < len(x)-1 {
			m[strings.ToLower(strings.TrimSpace(x[:i]))] = strings.TrimSpace(x[i+1:])
		}
	}
	return m
}
func normalizeRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "administrator":
		return "administrator"
	case "analyst", "operator", "network_operator", "security_admin":
		return "analyst"
	default:
		return "read_only"
	}
}
func (m *Manager) mapGroups(groups []string) string {
	role := normalizeRole(m.cfg.DefaultRole)
	rank := map[string]int{"read_only": 1, "analyst": 2, "administrator": 3}
	for _, g := range groups {
		k := strings.ToLower(strings.TrimSpace(g))
		if raw := m.roleMap[k]; raw != "" {
			r := normalizeRole(raw)
			if rank[r] > rank[role] {
				role = r
			}
		}
	}
	return role
}

func (m *Manager) Authenticate(ctx context.Context, username, password string) (Identity, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return Identity{}, errors.New("username and password required")
	}
	conn, e := m.dial(ctx)
	if e != nil {
		return Identity{}, e
	}
	defer conn.Close()
	id := 1
	dn := ""
	groups := []string{}
	if m.cfg.UserDNTemplate != "" {
		dn = strings.ReplaceAll(m.cfg.UserDNTemplate, "{username}", escapeDN(username))
	} else {
		if m.cfg.BindDN != "" {
			if e = bind(conn, id, m.cfg.BindDN, m.cfg.BindPassword); e != nil {
				return Identity{}, fmt.Errorf("LDAP service bind: %w", e)
			}
			id++
		}
		dn, groups, e = searchUser(conn, id, m.cfg.BaseDN, m.cfg.UserAttribute, username, m.cfg.GroupAttribute)
		if e != nil {
			return Identity{}, e
		}
		id++
	}
	if e = bind(conn, id, dn, password); e != nil {
		return Identity{}, errors.New("LDAP credentials rejected")
	}
	if len(groups) == 0 && m.cfg.BaseDN != "" {
		id++
		_, groups, _ = searchUser(conn, id, m.cfg.BaseDN, m.cfg.UserAttribute, username, m.cfg.GroupAttribute)
	}
	role := m.mapGroups(groups)
	return Identity{Username: username, DN: dn, Groups: groups, Role: role}, nil
}
func (m *Manager) dial(ctx context.Context) (net.Conn, error) {
	u, _ := url.Parse(m.cfg.URL)
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "ldaps" {
			host += ":636"
		} else {
			host += ":389"
		}
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	if u.Scheme == "ldaps" {
		tc := m.cfg.TLSConfig
		if tc == nil {
			tc = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
		}
		return tls.DialWithDialer(&d, "tcp", host, tc)
	}
	return d.DialContext(ctx, "tcp", host)
}

func encLen(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	if n < 256 {
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}
func tlv(tag byte, v []byte) []byte {
	o := []byte{tag}
	o = append(o, encLen(len(v))...)
	o = append(o, v...)
	return o
}
func encInt(v int) []byte {
	if v < 128 {
		return tlv(0x02, []byte{byte(v)})
	}
	return tlv(0x02, []byte{byte(v >> 8), byte(v)})
}
func oct(s string) []byte { return tlv(0x04, []byte(s)) }
func seq(parts ...[]byte) []byte {
	var v []byte
	for _, p := range parts {
		v = append(v, p...)
	}
	return tlv(0x30, v)
}
func ldapMsg(id int, op []byte) []byte { return seq(encInt(id), op) }
func bindReq(dn, pw string) []byte {
	v := append(encInt(3), oct(dn)...)
	v = append(v, tlv(0x80, []byte(pw))...)
	return tlv(0x60, v)
}
func bind(c net.Conn, id int, dn, pw string) error {
	if _, e := c.Write(ldapMsg(id, bindReq(dn, pw))); e != nil {
		return e
	}
	msg, e := readTLV(bufio.NewReader(c))
	if e != nil {
		return e
	}
	op, e := protocolOp(msg)
	if e != nil || op.tag != 0x61 {
		return errors.New("invalid LDAP bind response")
	}
	rc, _, e := readOne(op.val)
	if e != nil || rc.tag != 0x0a {
		return errors.New("LDAP bind response missing result code")
	}
	code := intBytes(rc.val)
	if code != 0 {
		return fmt.Errorf("LDAP bind result code %d", code)
	}
	return nil
}
func equality(attr, val string) []byte { return tlv(0xa3, append(oct(attr), oct(val)...)) }
func searchReq(base, attr, user, groupAttr string) []byte {
	filter := tlv(0xa0, append(equality("objectClass", "person"), equality(attr, user)...))
	attrs := seq(oct("distinguishedName"), oct(groupAttr))
	v := append(oct(base), tlv(0x0a, []byte{0x02})...)
	v = append(v, tlv(0x0a, []byte{0x00})...)
	v = append(v, encInt(2)...)
	v = append(v, encInt(5)...)
	v = append(v, tlv(0x01, []byte{0x00})...)
	v = append(v, filter...)
	v = append(v, attrs...)
	return tlv(0x63, v)
}
func searchUser(c net.Conn, id int, base, attr, user, groupAttr string) (string, []string, error) {
	if _, e := c.Write(ldapMsg(id, searchReq(base, attr, user, groupAttr))); e != nil {
		return "", nil, e
	}
	br := bufio.NewReader(c)
	dn := ""
	groups := []string{}
	for {
		msg, e := readTLV(br)
		if e != nil {
			return "", nil, e
		}
		op, e := protocolOp(msg)
		if e != nil {
			return "", nil, e
		}
		if op.tag == 0x64 {
			d, g, e := parseEntry(op.val, groupAttr)
			if e != nil {
				return "", nil, e
			}
			if dn != "" {
				return "", nil, errors.New("LDAP search returned multiple users")
			}
			dn = d
			groups = g
		} else if op.tag == 0x65 {
			rc, _, e := readOne(op.val)
			if e != nil {
				return "", nil, e
			}
			if intBytes(rc.val) != 0 {
				return "", nil, errors.New("LDAP search failed")
			}
			break
		}
	}
	if dn == "" {
		return "", nil, errors.New("LDAP user not found")
	}
	return dn, groups, nil
}
func escapeDN(s string) string {
	r := strings.NewReplacer("\\", "\\\\", ",", "\\,", "+", "\\+", "\"", "\\\"", "<", "\\<", ">", "\\>", ";", "\\;", "=", "\\=")
	return r.Replace(s)
}

type ber struct {
	tag byte
	val []byte
}

func readLen(r io.Reader) (int, error) {
	var b [1]byte
	if _, e := io.ReadFull(r, b[:]); e != nil {
		return 0, e
	}
	if b[0]&0x80 == 0 {
		return int(b[0]), nil
	}
	n := int(b[0] & 0x7f)
	if n < 1 || n > 4 {
		return 0, errors.New("invalid BER length")
	}
	buf := make([]byte, n)
	if _, e := io.ReadFull(r, buf); e != nil {
		return 0, e
	}
	v := 0
	for _, x := range buf {
		v = v<<8 | int(x)
	}
	if v > 4<<20 {
		return 0, errors.New("LDAP message too large")
	}
	return v, nil
}
func readTLV(r io.Reader) (ber, error) {
	var t [1]byte
	if _, e := io.ReadFull(r, t[:]); e != nil {
		return ber{}, e
	}
	n, e := readLen(r)
	if e != nil {
		return ber{}, e
	}
	v := make([]byte, n)
	if _, e = io.ReadFull(r, v); e != nil {
		return ber{}, e
	}
	return ber{t[0], v}, nil
}
func readOne(b []byte) (ber, []byte, error) {
	if len(b) < 2 {
		return ber{}, nil, io.ErrUnexpectedEOF
	}
	tag := b[0]
	i := 1
	first := b[i]
	i++
	n := 0
	if first&0x80 == 0 {
		n = int(first)
	} else {
		k := int(first & 0x7f)
		if k < 1 || k > 4 || i+k > len(b) {
			return ber{}, nil, errors.New("bad BER length")
		}
		for j := 0; j < k; j++ {
			n = n<<8 | int(b[i+j])
		}
		i += k
	}
	if i+n > len(b) {
		return ber{}, nil, io.ErrUnexpectedEOF
	}
	return ber{tag, b[i : i+n]}, b[i+n:], nil
}
func protocolOp(msg ber) (ber, error) {
	if msg.tag != 0x30 {
		return ber{}, errors.New("LDAP message not sequence")
	}
	_, rest, e := readOne(msg.val)
	if e != nil {
		return ber{}, e
	}
	op, _, e := readOne(rest)
	return op, e
}
func intBytes(b []byte) int {
	v := 0
	for _, x := range b {
		v = v<<8 | int(x)
	}
	return v
}
func parseEntry(v []byte, groupAttr string) (string, []string, error) {
	dnv, rest, e := readOne(v)
	if e != nil || dnv.tag != 0x04 {
		return "", nil, errors.New("bad search entry DN")
	}
	attrs, _, e := readOne(rest)
	if e != nil || attrs.tag != 0x30 {
		return "", nil, errors.New("bad search attributes")
	}
	groups := []string{}
	r := attrs.val
	for len(r) > 0 {
		pa, nr, e := readOne(r)
		if e != nil {
			return "", nil, e
		}
		r = nr
		if pa.tag != 0x30 {
			continue
		}
		name, rr, e := readOne(pa.val)
		if e != nil {
			continue
		}
		vals, _, e := readOne(rr)
		if e != nil || vals.tag != 0x31 {
			continue
		}
		if !strings.EqualFold(string(name.val), groupAttr) {
			continue
		}
		vv := vals.val
		for len(vv) > 0 {
			x, nx, e := readOne(vv)
			if e != nil {
				break
			}
			vv = nx
			if x.tag == 0x04 {
				groups = append(groups, string(x.val))
			}
		}
	}
	return string(dnv.val), groups, nil
}

// Helpers used by tests and troubleshooting.
func EncodeBindResult(id, code int) []byte {
	return ldapMsg(id, tlv(0x61, append(append(tlv(0x0a, []byte{byte(code)}), oct("")...), oct("")...)))
}
func EncodeSearchEntry(id int, dn, groupAttr string, groups []string) []byte {
	var vals []byte
	for _, g := range groups {
		vals = append(vals, oct(g)...)
	}
	pa := seq(oct(groupAttr), tlv(0x31, vals))
	entry := tlv(0x64, append(oct(dn), seq(pa)...))
	return ldapMsg(id, entry)
}
func EncodeSearchDone(id, code int) []byte {
	return ldapMsg(id, tlv(0x65, append(append(tlv(0x0a, []byte{byte(code)}), oct("")...), oct("")...)))
}
func DecodeMessageID(b []byte) (int, byte, error) {
	x, _, e := readOne(b)
	if e != nil {
		return 0, 0, e
	}
	if x.tag != 0x30 {
		return 0, 0, errors.New("not sequence")
	}
	id, rest, e := readOne(x.val)
	if e != nil {
		return 0, 0, e
	}
	op, _, e := readOne(rest)
	if e != nil {
		return 0, 0, e
	}
	return intBytes(id.val), op.tag, nil
}
func ReadPacket(r io.Reader) ([]byte, error) {
	br := bufio.NewReader(r)
	x, e := readTLV(br)
	if e != nil {
		return nil, e
	}
	return tlv(x.tag, x.val), nil
}
func PortFromURL(raw string) int {
	u, _ := url.Parse(raw)
	if p, _ := strconv.Atoi(u.Port()); p > 0 {
		return p
	}
	if u.Scheme == "ldaps" {
		return 636
	}
	return 389
}

var _ = binary.BigEndian
