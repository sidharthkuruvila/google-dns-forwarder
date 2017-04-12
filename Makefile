all: dns_forwarder

dns_forwarder: dns_forwarder.ml
	ocamlfind ocamlopt dns_forwarder.ml -package lwt,dns.lwt,cohttp.lwt,ppx_deriving_yojson,ppx_deriving.show,str -linkpkg -g -o dns_forwarder

clean:
	rm -f dns_forwarder dns_forwarder.cmi dns_forwarder.cmx dns_forwarder.o
