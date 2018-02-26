# proxyv2 [![Go Report Card](https://goreportcard.com/badge/github.com/wolfeidau/proxyv2)](https://goreportcard.com/report/github.com/wolfeidau/proxyv2)

This [Go](https://golang.org) library wraps any TCP based listener and provides [proxy protocol](docs/proxy-protocol.txt) v2 support. 

# usage

Go get the package.

```
go get -u -v github.com/wolfeidau/proxyv2
```

Example code.

```go
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		// handle err
		log.Fatal(err)
	}

	config := &lnkproxy.Config{
		Trace:            func(pc *proxyv2.ProxyConn) {}, // run on connection close
		ProxyHeaderError: func(err error) {},
	}

	proxyln, err := lnkproxy.NewListener(ln, config)
	if err != nil {
		// handle err
		log.Fatal(err)
	}
```

# license

This code is released under MIT License, and is copyright Mark Wolfe.
