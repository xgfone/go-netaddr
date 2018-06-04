# netaddr

This is a Go implemenation of `IPAddress` and `IPNetwork` in the Python package [`netaddr`](https://pypi.org/project/netaddr/). See [godoc](https://godoc.org/github.com/xgfone/netaddr).

## Usage

#### IP Address

```go
// IPv6
ip := MustNewIPAddress("fe80::d656:43a8:fc42:948c")
fmt.Println(ip) // fe80::d656:43a8:fc42:948c

v1 := ip.Value()
fmt.Println(ip.Equal(MustNewIPAddress(v1, ip.Version()))) // true

// IPv4
ip = MustNewIPAddress("192.168.10.10")
fmt.Println(ip) // 192.168.10.10

v2 := ip.Value()
fmt.Println(ip.Equal(MustNewIPAddress(v2, ip.Version()))) // true
```

#### IP Network

```go
net := MustNewIPNetwork("192.168.10.10/24")

fmt.Println(net.Network()) // 192.168.10.0
fmt.Println(net.Broadcast()) // 192.168.10.255
fmt.Println(net.NetworkMask()) // 255.255.255.0
fmt.Println(net.HostMask()) // 0.0.0.255
fmt.Println(net.First()) // 192.168.10.0
fmt.Println(net.Last()) // 192.168.10.255
fmt.Println(net.CIDR()) // 192.168.10.0/24
fmt.Println(net.HasStringIP("192.168.10.0")) // true
fmt.Println(net.HasStringIP("192.168.11.0")) // false
fmt.Println(net.Size()) // 16
fmt.Println(net.Previous()) // 192.168.9.0/24
fmt.Println(net.Next()) // 192.168.11.0/24
fmt.Println(net.Contains(MustNewIPNetwork("192.168.10.0/28"))) // true
```
