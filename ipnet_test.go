package netaddr

import (
	"fmt"
)

func ExampleIPNetwork_Network() {
	net := MustNewIPNetwork("192.168.10.10/24")
	fmt.Println(net.Network())

	net = MustNewIPNetwork("fe80::d656:43a8:fc42:948c/124")
	fmt.Println(net.Network())

	// Output:
	// 192.168.10.0
	// fe80::d656:43a8:fc42:9480
}

func ExampleIPNetwork_Broadcast() {
	net := MustNewIPNetwork("192.168.10.10/24")
	fmt.Println(net.Broadcast())

	net = MustNewIPNetwork("fe80::d656:43a8:fc42:948c/124")
	fmt.Println(net.Broadcast())

	// Output:
	// 192.168.10.255
	// fe80::d656:43a8:fc42:948f
}

func ExampleIPNetwork_NetworkMask() {
	net := MustNewIPNetwork("192.168.10.10/24")
	fmt.Println(net.NetworkMask())

	net = MustNewIPNetwork("fe80::d656:43a8:fc42:948c/124")
	fmt.Println(net.NetworkMask())

	// Output:
	// 255.255.255.0
	// ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff0
}

func ExampleIPNetwork_HostMask() {
	net := MustNewIPNetwork("192.168.10.10/24")
	fmt.Println(net.HostMask())

	net = MustNewIPNetwork("fe80::d656:43a8:fc42:948c/124")
	fmt.Println(net.HostMask())

	// Output:
	// 0.0.0.255
	// ::f
}

func ExampleIPNetwork_First() {
	net := MustNewIPNetwork("192.168.10.10/24")
	fmt.Println(net.First())

	net = MustNewIPNetwork("fe80::d656:43a8:fc42:948c/124")
	fmt.Println(net.First())

	// Output:
	// 192.168.10.0
	// fe80::d656:43a8:fc42:9480
}

func ExampleIPNetwork_Last() {
	net := MustNewIPNetwork("192.168.10.10/24")
	fmt.Println(net.Last())

	net = MustNewIPNetwork("fe80::d656:43a8:fc42:948c/124")
	fmt.Println(net.Last())

	// Output:
	// 192.168.10.255
	// fe80::d656:43a8:fc42:948f
}

func ExampleIPNetwork_CIDR() {
	net := MustNewIPNetwork("192.168.10.10/24")
	fmt.Println(net.CIDR())

	net = MustNewIPNetwork("fe80::d656:43a8:fc42:948c/124")
	fmt.Println(net.CIDR())

	// Output:
	// 192.168.10.0/24
	// fe80::d656:43a8:fc42:9480/124
}

func ExampleIPNetwork_Size() {
	net := MustNewIPNetwork("192.168.10.10/22")
	fmt.Printf("%.0f\n", net.Size())

	net = MustNewIPNetwork("fe80::/16")
	fmt.Printf("%.0f\n", net.Size())

	net = MustNewIPNetwork("fe80::/118")
	fmt.Printf("%.0f\n", net.Size())

	net = MustNewIPNetwork("fe80::d656:43a8:fc42:948c/124")
	fmt.Printf("%.0f\n", net.Size())

	// Output:
	// 1024
	// 5192296858534827628530496329220096
	// 1024
	// 16
}

func ExampleIPNetwork_HasStringIP() {
	net := MustNewIPNetwork("192.168.10.10/24")
	fmt.Println(net.HasStringIP("192.168.10.0"))
	fmt.Println(net.HasStringIP("192.168.11.0"))

	net = MustNewIPNetwork("fe80::d656:43a8:fc42:948c/124")
	fmt.Println(net.HasStringIP("fe80::d656:43a8:fc42:9481"))
	fmt.Println(net.HasStringIP("fe80::d656:43a8:fc42:9400"))

	// Output:
	// true
	// false
	// true
	// false
}

func ExampleIPNetwork_Walk() {
	net := MustNewIPNetwork("192.168.10.240/28")
	net.Walk(func(ip IPAddress) {
		fmt.Println(ip)
	})

	net = MustNewIPNetwork("fe80::d656:43a8:fc42:948c/124")
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
	// fe80::d656:43a8:fc42:9480
	// fe80::d656:43a8:fc42:9481
	// fe80::d656:43a8:fc42:9482
	// fe80::d656:43a8:fc42:9483
	// fe80::d656:43a8:fc42:9484
	// fe80::d656:43a8:fc42:9485
	// fe80::d656:43a8:fc42:9486
	// fe80::d656:43a8:fc42:9487
	// fe80::d656:43a8:fc42:9488
	// fe80::d656:43a8:fc42:9489
	// fe80::d656:43a8:fc42:948a
	// fe80::d656:43a8:fc42:948b
	// fe80::d656:43a8:fc42:948c
	// fe80::d656:43a8:fc42:948d
	// fe80::d656:43a8:fc42:948e
	// fe80::d656:43a8:fc42:948f
}
