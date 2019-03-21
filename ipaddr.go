// Copyright 2018 xgfone
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netaddr

import (
	"bytes"
	"fmt"
	"math/big"
	"net"
	"strings"
)

// IPAddress represents a IPv4/IPv6 address.
type IPAddress struct {
	ip      net.IP
	version int
}

// NewIPAddress returns a new IPAddress.
//
// The argument, ip, is a IPv4 or IPv6 address, which maybe a string, []byte,
// [4]byte, [6]byte, net.IP or *big.Int.
//
// For net.IP and *big.Int, the version is necessary, which reprensents
// the verion of the IP address, that's, 4 or 6.
//
// For []byte, the version is necessary if the length of bytes is not 4 or 16.
//
// For string, it maybe either a ipv4/ipv6 address or a integer string.
// If it's a integer string, it represents the integer value of the ipv4/ipv6,
// and must appoint the version explicitly.
func NewIPAddress(ip interface{}, version ...int) (IPAddress, error) {
	var _ip net.IP
	var _version int

	if len(version) > 0 {
		_version = version[0]
		if _version != 4 && _version != 6 {
			return IPAddress{}, fmt.Errorf("version must be 4 or 6")
		}
	}

	switch v := ip.(type) {
	case string:
		if _ip = net.ParseIP(v); _ip == nil {
			bi, ok := new(big.Int).SetString(v, 10)
			if !ok {
				return IPAddress{}, fmt.Errorf("'%s' is not a valid ipv4/ipv6", ip)
			}
			if _version == 0 {
				return IPAddress{}, fmt.Errorf("missing the argument 'version'")
			}
			return NewIPAddress(bi.Bytes(), _version)
		}

		if _version == 0 {
			if strings.Contains(v, ":") {
				_version = 6
			} else {
				_version = 4
			}
		}
	case []byte:
		switch _len := len(v); _len {
		case net.IPv4len:
			_version = 4
			// _ip = net.IPv4(v[0], v[1], v[2], v[3])
			_ip = net.IP(v)
		case net.IPv6len:
			_version = 6
			_ip = net.IP(v)
		default:
			switch _version {
			case 4:
				if _len > net.IPv4len {
					return IPAddress{}, fmt.Errorf("the bytes is too long")
				} else if _len < net.IPv4len {
					bs := [net.IPv4len]byte{}
					copy(bs[net.IPv4len-_len:], v)
					v = bs[:]
				}
				// _ip = net.IPv4(v[0], v[1], v[2], v[3])
				_ip = net.IP(v)
			case 6:
				if _len > net.IPv6len {
					return IPAddress{}, fmt.Errorf("the bytes is too long")
				} else if _len < net.IPv6len {
					bs := [net.IPv6len]byte{}
					copy(bs[net.IPv6len-_len:], v)
					v = bs[:]
				}
				_ip = net.IP(v)

			default:
				return IPAddress{}, fmt.Errorf("missing the argument 'version'")
			}
		}
	case [4]byte:
		_version = 4
		// _ip = net.IPv4(v[0], v[1], v[2], v[3])
		_ip = net.IP(v[:])
	case [16]byte:
		_version = 6
		_ip = net.IP(v[:])
	case net.IP:
		if _version == 0 {
			return IPAddress{}, fmt.Errorf("missing the argument 'version'")
		}
		_ip = v
	case *big.Int:
		if _version == 0 {
			return IPAddress{}, fmt.Errorf("missing the argument 'version'")
		}
		return NewIPAddress(v.Bytes(), _version)
	default:
		return IPAddress{}, fmt.Errorf("does not support the type '%T'", ip)
	}

	switch _version {
	case 4:
		return IPAddress{ip: _ip.To4(), version: 4}, nil
	case 6:
		return IPAddress{ip: _ip.To16(), version: 6}, nil
	default:
		return IPAddress{}, fmt.Errorf("the version '%d' is not 4 or 6", _version)
	}
}

// MustNewIPAddress is the same as NewIPAddress, but panic if an error occurs.
func MustNewIPAddress(ip interface{}, version ...int) IPAddress {
	addr, err := NewIPAddress(ip, version...)
	if err != nil {
		panic(err)
	}
	return addr
}

// IsValid reports whether the ip address is valid.
func (ip IPAddress) IsValid() bool {
	v := ip.version
	_len := len(ip.ip)
	return (v == 4 && _len == 4) || (v == 6 && _len == 16) || false
}

// String returns a string representation of the ip address.
//
// It will return "" if the ip address is invalid.
func (ip IPAddress) String() string {
	if ip.IsValid() {
		return ip.ip.String()
	}
	return ""
}

// Bytes returns a []byte representation of the ip address.
func (ip IPAddress) Bytes() []byte {
	return []byte(ip.ip)
}

// Version returns the version of ip.
func (ip IPAddress) Version() int {
	return ip.version
}

// IP converts the ip to the type, net.IP.
func (ip IPAddress) IP() net.IP {
	return ip.ip
}

// IPv4 returns a new IPv4 IPAddress.
func (ip IPAddress) IPv4() IPAddress {
	if ip.version == 4 {
		return ip
	}
	return IPAddress{ip: ip.ip.To4(), version: 4}
}

// IPv6 returns a new IPv6 IPAddress.
func (ip IPAddress) IPv6() IPAddress {
	if ip.version == 6 {
		return ip
	}
	return IPAddress{ip: ip.ip.To16(), version: 6}
}

// Value returns the integer string representation of the ipv4/ipv6 address.
func (ip IPAddress) Value() string {
	bi := ip.BigInt()
	if bi == nil {
		return ""
	}
	return bi.String()
}

func (ip IPAddress) toBinary(sep string) string {
	buf := bytes.NewBuffer(nil)
	if ip.version == 6 {
		buf.Grow(144)
	} else {
		buf.Grow(36)
	}
	buf.Grow(128)
	for _, b := range ip.ip {
		buf.WriteString(fmt.Sprintf("%08b%s", b, sep))
	}
	return buf.String()[:buf.Len()-len(sep)]
}

// Binary returns the binary format of the IP address.
//
// For example, "10101010101010101010101010101010".
func (ip IPAddress) Binary() string {
	return ip.toBinary("")
}

// Bits returns the binary format of the IP address separated by the dot.
//
// For example, "10101010.10101010.10101010.10101010".
func (ip IPAddress) Bits() string {
	return ip.toBinary(".")
}

// Hex returns the hexadecimal format of the IP address.
//
// For example, "c0a80a0a".
func (ip IPAddress) Hex() string {
	buf := bytes.NewBuffer(nil)
	if ip.version == 6 {
		buf.Grow(32)
	} else {
		buf.Grow(8)
	}

	var ok bool
	for _, b := range ip.ip {
		if b == 0 {
			if !ok {
				continue
			}
		}
		if !ok {
			ok = true
		}
		buf.WriteString(fmt.Sprintf("%02x", b))
	}
	return buf.String()[:buf.Len()]
}

// BigInt returns the big integer representation of the ipv4/ipv6 address.
func (ip IPAddress) BigInt() *big.Int {
	switch ip.version {
	case 4:
		return new(big.Int).SetBytes(ip.IPv4().Bytes())
	case 6:
		return new(big.Int).SetBytes(ip.IPv6().Bytes())
	}
	return nil
}

// Network returns the network of the ip address.
func (ip IPAddress) Network() (net IPNetwork) {
	var err error
	switch ip.version {
	case 4:
		net, err = NewIPNetworkFromIPAddress(ip, ipv4MaxBit)
	case 6:
		net, err = NewIPNetworkFromIPAddress(ip, ipv6MaxBit)
	default:
		return IPNetwork{}
	}
	if err != nil {
		panic(err)
	}
	return net
}

// Equal reports whether ip is equal to other.
func (ip IPAddress) Equal(other IPAddress) bool {
	return ip.ip.Equal(other.ip)
}

// Compare returns an integer comparing two IPAddresses.
// The result will be 0 if ip==other, -1 if ip < other, and +1 if ip > other.
func (ip IPAddress) Compare(other IPAddress) int {
	len1 := len(ip.ip)
	len2 := len(other.ip)
	if len1 != len2 {
		panic(fmt.Errorf("the version is not consistent"))
	}

	for i := 0; i < len1; i++ {
		if ip.ip[i] > other.ip[i] {
			return 1
		} else if ip.ip[i] < other.ip[i] {
			return -1
		}
	}

	return 0
}

// Less reports whether ip is less than other.
func (ip IPAddress) Less(other IPAddress) bool {
	return ip.Compare(other) < 0
}

// IsIPv4 reports whether the ip address is ipv4.
func (ip IPAddress) IsIPv4() bool {
	return ip.version == 4
}

// IsIPv6 reports whether the ip address is ipv6.
func (ip IPAddress) IsIPv6() bool {
	return ip.version == 6
}

// IsUnspecified reports whether ip is an unspecified address, either
// the IPv4 address "0.0.0.0" or the IPv6 address "::".
func (ip IPAddress) IsUnspecified() bool {
	return ip.ip.IsUnspecified()
}

// IsInterfaceLocalMulticast reports whether ip is
// an interface-local multicast address. that's, ff01::/16.
func (ip IPAddress) IsInterfaceLocalMulticast() bool {
	return ip.ip.IsInterfaceLocalMulticast()
}

// IsLinkLocalMulticast reports whether ip is a link-local multicast address,
// that's, 224.0.0.0/24 or ff02::/16.
func (ip IPAddress) IsLinkLocalMulticast() bool {
	return ip.ip.IsLinkLocalMulticast()
}

// IsLinkLocalUnicast reports whether ip is a link-local unicast address,
// that's, 169.254.0.0/16 or fe80::/10.
func (ip IPAddress) IsLinkLocalUnicast() bool {
	return ip.ip.IsLinkLocalUnicast()
}

// IsGlobalUnicast reports whether ip is a global unicast
// address.
//
// The identification of global unicast addresses uses address type
// identification as defined in RFC 1122, RFC 4632 and RFC 4291 with
// the exception of IPv4 directed broadcast addresses.
// It returns true even if ip is in IPv4 private address space or
// local IPv6 unicast address space.
//
// They are not
//    0.0.0.0  255.255.255.255  127.0.0.0/8  169.254.0.0/16  224.0.0.0/4
//    ::  ::1  fe80::/10  ff00::/8
func (ip IPAddress) IsGlobalUnicast() bool {
	return ip.ip.IsGlobalUnicast()
}

// IsUnicast reports whether the ip address is the unicast
func (ip IPAddress) IsUnicast() bool {
	return !ip.IsMulticast()
}

// IsMulticast reports whether the ip address is the multicast,
// that's, 224.0.0.0/4 or ff00::/8.
func (ip IPAddress) IsMulticast() bool {
	return ip.ip.IsMulticast()
}

// IsLoopback reports whether the ip address is the loopback,
// that's, 127.0.0.1/8 or ::1.
func (ip IPAddress) IsLoopback() bool {
	return ip.ip.IsLoopback()
}

// Add returns a new IPAddress with its numerical value increased by num.
func (ip IPAddress) Add(num int64) IPAddress {
	old := ip.BigInt()
	old.Add(old, big.NewInt(num))
	return MustNewIPAddress(old.Bytes(), ip.version)
}

// Sub returns a new IPAddress with its numerical value decreased by num.
func (ip IPAddress) Sub(num int64) IPAddress {
	old := ip.BigInt()
	old.Sub(old, big.NewInt(num))
	return MustNewIPAddress(old.Bytes(), ip.version)
}
