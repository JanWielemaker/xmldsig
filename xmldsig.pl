:- module(xmldsig,
	  [ xmld_signed_DOM/3			% +DOM, -SignedDOM, +Options
	  ]).
:- use_module(library(option)).
:- use_module(library(sha)).
:- use_module(library(ssl)).
:- use_module(library(base64)).
:- use_module(library(debug)).
:- use_module('../c14n2/c14n2').

/** <module> XML Digital signature

This library deals with _XMLDSIG_, RSA signed XML documents.

@see http://www.di-mgt.com.au/xmldsig.html
@see https://www.bmt-online.org/geekisms/RSA_verify
@see http://stackoverflow.com/questions/5576777/whats-the-difference-between-nid-sha-and-nid-sha1-in-openssl
*/

xmldsig_ns('http://www.w3.org/2000/09/xmldsig#').

%%	xmld_signed_DOM(+DOM, -SignedDOM, +Options) is det.
%
%	Translate an XML DOM structure in a signed version.  Options:
%
%	  - key_file(+File)
%	  File holding the private key needed to sign
%	  - key_password(+Password)
%	  String holding the password to op the private key.

xmld_signed_DOM(DOM, SignedDOM, Options) :-
	dom_hash(DOM, ODOM, Hash, Options),
	signed_info(Hash, Signature, SDOM, KeyDOM, Options),
	signed_xml_dom(ODOM, SDOM, KeyDOM, Signature, SignedDOM, Options).

%%	dom_hash(+DOM, -ODOM, -Hash, +Options) is det.
%
%	Compute the digest for DOM.
%
%	@arg Hash is the base64  encoded   version  of  the selected SHA
%	algorithm.

dom_hash(DOM, ODOM, Hash, Options) :-
	object_c14n(DOM, ODOM, C14N),
	hash(C14N, Hash, Options).

object_c14n(DOM, ODOM, C14N) :-
	object_dom(DOM, ODOM),
	with_output_to(
	    string(C14N),
	    xml_write_canonical(current_output, ODOM)).

object_dom(DOM0,
	   element(NS:'Object', ['Id'='object', xmlns=NS], DOM)) :-
	xmldsig_ns(NS),
	to_list(DOM0, DOM).

to_list(DOM, DOM) :- DOM = [_|_].
to_list(DOM, [DOM]).

hash(C14N, Hash, Options) :-
	option(hash(Algo), Options, sha1),
	sha_hash(C14N, HashCodes, [algrithm(Algo)]),
	phrase(base64(HashCodes), Base64Codes),
	string_codes(Hash, Base64Codes).

%%	signed_info(+Hash, -Signature, -SDOM, -KeyDOM, +Options)

signed_info(Hash, Signature, SDOM, KeyDOM, Options) :-
	signed_info_dom(Hash, SDOM, Options),
	with_output_to(
	    string(SignedInfo),
	    xml_write_canonical(current_output, SDOM)),
	rsa_signature(SignedInfo, Signature, KeyDOM, Options).

%%	signed_info_dom(+Hash, -SDOM, +Options) is det.
%
%	True when SDOM is the xmldsign:Signature  DOM for an object with
%	the given Hash.

signed_info_dom(Hash, SDOM, _Options) :-
	SDOM = element(NS:'SignedInfo', [xmlns=NS],
		       [ '\n  ',
			 element(NS:'CanonicalizationMethod',
				 ['Algorithm'=C14NAlgo], []),
			 '\n  ',
			 element(NS:'SignatureMethod',
				 ['Algorithm'=SignatureMethod], []),
			 '\n  ',
			 Reference,
			 '\n'
		       ]),
	Reference = element(NS:'Reference', ['URI'='#object'],
			    [ '\n    ',
			      element(NS:'DigestMethod',
				      ['Algorithm'=DigestMethod], []),
			      '\n    ',
			      element(NS:'DigestValue', [], [Hash]),
			      '\n  '
			    ]),
	xmldsig_ns(NS),
	DigestMethod='http://www.w3.org/2000/09/xmldsig#sha1',
	C14NAlgo='http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
	SignatureMethod='http://www.w3.org/2000/09/xmldsig#rsa-sha1'.

%%	rsa_signature(+SignedInfo:string, -Signature, -KeyDOM, +Options)

rsa_signature(SignedInfo, Signature, KeyDOM, Options) :-
	sha_hash(SignedInfo, Digest, [algorithm(sha1)]),
	hash_atom(Digest, Hex),
	string_upper(Hex, HEX),
	debug(xmldsig, 'SignedInfo SHA1 digest = ~p', [HEX]),
	private_key(Key, Options),
	rsa_key_dom(Key, KeyDOM),
	rsa_sign(Key, Digest, String,
		 [ type(sha1),
		   encoding(octet)
		 ]),
	string_length(String, Len),
	debug(xmldsig, 'RSA signatute length: ~p', [Len]),
	string_codes(String, Codes),
	phrase(base64(Codes), Codes64),
	string_codes(Signature, Codes64).

private_key(Key, Options) :-
	option(key_file(File), Options),
	option(key_password(Password), Options), !,
	setup_call_cleanup(
	    open(File, read, In, [type(binary)]),
	    load_private_key(In, Password, Key),
	    close(In)).
private_key(_Key, Options) :-
	\+ option(key_file(_), Options), !,
	throw(error(existence_error(option, key_file, Options),_)).
private_key(_Key, Options) :-
	throw(error(existence_error(option, key_password, Options),_)).


%%	rsa_key_dom(+Key, -DOM) is det.
%
%	Produce the KeyInfo node from the private key.

rsa_key_dom(Key,
	    element(NS:'KeyInfo', [xmlns=NS],
		    [ element(NS:'KeyValue', [],
			      [ '\n  ',
				element(NS:'RSAKeyValue', [],
					[ '\n    ',
					  element(NS:'Modulus', [], [Modulus]),
					  '\n    ',
					  element(NS:'Exponent', [], [Exponent]),
					  '\n  '
					]),
				'\n'
			      ])
		    ])) :-
	key_info(Key, Info),
	_{modulus:Modulus, exponent:Exponent} :< Info,
	xmldsig_ns(NS).


%%	key_info(+Key, -Info) is det.
%
%	Extract the RSA modulus and exponent   from a private key. These
%	are the first end  second  field  of   the  rsa  term.  They are
%	represented as hexadecimal encoded bytes. We must recode this to
%	base64.
%
%	@tbd	Provide better support from library(ssl).

key_info(private_key(Key), rsa{modulus:Modulus, exponent:Exponent}) :- !,
	base64_bignum_arg(1, Key, Modulus),
	base64_bignum_arg(2, Key, Exponent).
key_info(Key, _) :-
	type_error(private_key, Key).

base64_bignum_arg(I, Key, Value) :-
	arg(I, Key, HexModulesString),
	string_codes(HexModulesString, HexModules),
	phrase(hex_bytes(Bytes), HexModules),
	phrase(base64(Bytes), Bytes64),
	string_codes(Value, Bytes64).

hex_bytes([H|T]) -->
	xdigit(D1), xdigit(D2), !,
	{ H is D1<<4+D2 },
	hex_bytes(T).
hex_bytes([]) --> [].


signed_xml_dom(ObjectDOM, SDOM, KeyDOM, Signature, SignedDOM, _Options) :-
	SignedDOM = element(NS:'Signature', [xmlns=NS],
			    [ '\n', SDOM,
			      '\n', element(NS:'SignatureValue', [], [Signature]),
			      '\n', KeyDOM,
			      '\n', ObjectDOM,
			      '\n'
			    ]),
	xmldsig_ns(NS).
