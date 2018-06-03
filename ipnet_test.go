package netaddr

import (
	"fmt"
)

func ExampleIPNetwork_Network() {
	net := MustNewIPNetwork("192.168.10.10/24")
	fmt.Println(net.Network())

	// Output:
	// 192.168.10.0
}

func ExampleIPNetwork_Broadcast() {
	net := MustNewIPNetwork("192.168.10.10/24")
	fmt.Println(net.Broadcast())

	// Output:
	// 192.168.10.255
}

func ExampleIPNetwork_NetworkMask() {
	net := MustNewIPNetwork("192.168.10.10/24")
	fmt.Println(net.NetworkMask())

	// Output:
	// 255.255.255.0
}

func ExampleIPNetwork_HostMask() {
	net := MustNewIPNetwork("192.168.10.10/24")
	fmt.Println(net.HostMask())

	// Output:
	// 0.0.0.255
}

func ExampleIPNetwork_First() {
	net := MustNewIPNetwork("192.168.10.10/24")
	fmt.Println(net.First())

	// Output:
	// 192.168.10.0
}

func ExampleIPNetwork_Last() {
	net := MustNewIPNetwork("192.168.10.10/24")
	fmt.Println(net.Last())

	// Output:
	// 192.168.10.255
}

func ExampleIPNetwork_CIDR() {
	net := MustNewIPNetwork("192.168.10.10/24")
	fmt.Println(net.CIDR())

	// Output:
	// 192.168.10.0/24
}

func ExampleIPNetwork_Size() {
	net := MustNewIPNetwork("192.168.10.10/22")
	fmt.Printf("%.0f\n", net.Size())

	net = MustNewIPNetwork("fe80::/16")
	fmt.Printf("%.0f\n", net.Size())

	net = MustNewIPNetwork("fe80::/118")
	fmt.Printf("%.0f\n", net.Size())

	// Output:
	// 1024
	// 5192296858534827628530496329220096
	// 1024
}

func ExampleIPNetwork_HasStringIP() {
	net := MustNewIPNetwork("192.168.10.10/24")
	fmt.Println(net.HasStringIP("192.168.10.0"))
	fmt.Println(net.HasStringIP("192.168.11.0"))

	// Output:
	// true
	// false
}

func ExampleIPNetwork_Walk() {
	net := MustNewIPNetwork("192.168.10.240/28")
	net.Walk(func(ip IPAddress) {
		fmt.Println(ip)
	})

	// Output:
	// 192.168.10.240
	// 192.168.10.241
	// 192.168.10.242
	// 192.168.10.243
	// 192.168.10.244
	// 192.168.10.245
	// 192.168.10.246
	// 192.168.10.247
	// 192.168.10.248
	// 192.168.10.249
	// 192.168.10.250
	// 192.168.10.251
	// 192.168.10.252
	// 192.168.10.253
	// 192.168.10.254
	// 192.168.10.255
}
