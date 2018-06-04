package netaddr

import (
	"fmt"
)

func ExampleIPAddress() {
	// IPv6
	ip, err := NewIPAddress("fe80::d656:43a8:fc42:948c")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(ip, ip.IsValid())

	v1, v2 := ip.IPv6Value()
	fmt.Println(ip.Equal(NewIPAddressByUint64(v1, v2)))

	fmt.Println(ip.IsGlobalUnicast())
	fmt.Println(ip.IsInterfaceLocalMulticast())
	fmt.Println(ip.IsLinkLocalMulticast())
	fmt.Println(ip.IsLinkLocalUnicast())
	fmt.Println(ip.IsLoopback())
	fmt.Println(ip.IsMulticast())

	// Ipv4
	ip, err = NewIPAddress("192.168.10.10")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(ip, ip.IsValid())
	fmt.Println(ip.Bytes())

	v1 = ip.IPv4Value()
	fmt.Println(ip.Equal(NewIPAddressByUint64(v1)))

	fmt.Println(ip.IsGlobalUnicast())
	fmt.Println(ip.IsInterfaceLocalMulticast())
	fmt.Println(ip.IsLinkLocalMulticast())
	fmt.Println(ip.IsLinkLocalUnicast())
	fmt.Println(ip.IsLoopback())
	fmt.Println(ip.IsMulticast())

	// Loopback
	ip, _ = NewIPAddress("127.0.0.1")
	fmt.Println(ip.IsLoopback())
	ip, _ = NewIPAddress("::1")
	fmt.Println(ip.IsLoopback())

	// Output:
	// fe80::d656:43a8:fc42:948c true
	// true
	// false
	// false
	// false
	// true
	// false
	// false
	// 192.168.10.10 true
	// [192 168 10 10]
	// true
	// true
	// false
	// false
	// false
	// false
	// false
	// true
	// true
}

func ExampleIPAddress_Value() {
	ip1, _ := NewIPAddress("fe80::")
	ip2, _ := NewIPAddress(ip1.Value(), ip1.Version())

	fmt.Println(ip1)
	fmt.Println(ip2)
	fmt.Println(ip1.Equal(ip2))

	// Output:
	// fe80::
	// fe80::
	// true
}
