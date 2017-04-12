Google DNS Forwarder
--------------------

This is simple dns server that forwards requests to google's [http based dns server](https://developers.google.com/speed/public-dns/docs/dns-over-https). 

It's based on the example dns forwarder in https://github.com/mirage/ocaml-dns

It's quite crashy

Getting started
---------------
### Install the dependencies

```bash
opam install lwt
opam install dns
opam install cohttp
opam install tls
opam install ppx_deriving_yojson
```

### Build the package

```bash
make
```

### Run the program

```bash
sudo ./dns_forwarder
```


### Testing 


```
$ nslookup google.com 127.0.0.1
Server:		127.0.0.1
Address:	127.0.0.1#53

Non-authoritative answer:
Name:	google.com
Address: 172.217.26.174

```