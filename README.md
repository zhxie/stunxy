# stunxy

**stunxy** is a tool dealing with NAT traversal using STUN ([RFC 3489](https://tools.ietf.org/html/rfc3489)).

## Usage

```
# Use default server stun.ekiga.net:3478
stunxy

# Designate a STUN server and use SOCKS proxy
stunxy <ADDRESS> -s <ADDRESS>
```

### Args

`<ADDRESS>`: Server, default as `stun.ekiga.net`.

### Flags

`-h, --help`: Prints help information.

`-V, --version`: Prints version information.

### Options

`-p, --port <VALUE>`: Port, default as `3478`.

`-s, --socks-proxy <ADDRESS>`: SOCKS proxy. Only support SOCKS5 proxy.

`-w, --timeout <VALUE>`: Timeout to wait for each response, `0` as no timeout, default as `3000` ms.

## License

stunxy is licensed under [the MIT License](/LICENSE).
