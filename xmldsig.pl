:- module(xmldsig,
	  [
	  ]).
:- use_module(library(option)).
:- use_module(library(sha)).
:- use_module(library(base64)).
:- use_module('../c14n2/c14n2').

/** <module> XML Digital signature

@see http://www.di-mgt.com.au/xmldsig.html
*/

%%	Write a signed XML document to Stream for DOM.  Options:
%
%

xmldsigned_DOM(DOM, SignedDOM, Options) :-
	dom_hash(DOM, Hash, Options),
	signed_info_dom(Hash, SDOM, Options),
	with_output_to(
	    string(SignedInfo),
	    xml_write_canonical(current_output, SDOM)),
	rsa_signature(SignedInfo, Signature, Options),
	signed_xml_dom(Signature, SignedDOM, Options).

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
	NS = 'http://www.w3.org/2000/09/xmldsig#',
	to_list(DOM0, DOM).

to_list(DOM, DOM) :- DOM = [_|_].
to_list(DOM, [DOM]).

hash(C14N, Hash, Options) :-
	option(hash(Algo), Options, sha1),
	sha_hash(C14N, HashCodes, [algrithm(Algo)]),
	phrase(base64(HashCodes), Base64Codes),
	string_codes(Hash, Base64Codes).
