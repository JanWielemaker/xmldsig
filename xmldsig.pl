:- module(xmldsig,
	  [
	  ]).
:- use_module(library(option)).
:- use_module(library(sha)).
:- use_module(library(ssl)).
:- use_module(library(base64)).
:- use_module('../c14n2/c14n2').

/** <module> XML Digital signature

@see http://www.di-mgt.com.au/xmldsig.html
*/

xmldsig_ns('http://www.w3.org/2000/09/xmldsig#').

%%	Write a signed XML document to Stream for DOM.  Options:
%
%

xmldsigned_DOM(DOM, SignedDOM, Options) :-
	dom_hash(DOM, Hash, Options),
	signed_info(Hash, SDOM, Signature, Options),
	signed_xml_dom(DOM, SDOM, Signature, SignedDOM, Options).

%%	dom_hash(+DOM, -Hash, +Options) is det.
%
%	Compute the digest for DOM.
%
%	@arg Hash is the base64  encoded   version  of  the selected SHA
%	algorithm.

dom_hash(DOM, Hash, Options) :-
	object_c14n(DOM, C14N),
	hash(C14N, Hash, Options).

object_c14n(DOM, C14N) :-
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

%%	signed_info(+Hash, -Signature, -SDOM, +Options)

signed_info(Hash, Signature, SDOM, Options) :-
	signed_info_dom(Hash, SDOM, Options),
	with_output_to(
	    string(SignedInfo),
	    xml_write_canonical(current_output, SDOM)),
	writeln(SignedInfo),
	rsa_signature(SignedInfo, Signature, Options).

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

%%	rsa_signature(+SignedInfo:string, -Signature, +Options)

rsa_signature(SignedInfo, Signature, Options) :-
	sha_hash(SignedInfo, DigestCodes, [algrithm(sha1)]),
	hash_atom(DigestCodes, Hex),
	string_upper(Hex, Digest),
	debug(xmldsig, 'SignedInfo SHA1 digest = ~p', [Digest]),
	private_key(Key, Options),
	rsa_sign(Key, Digest, String,
		 [ type(md5_sha1)
		 ]),
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
