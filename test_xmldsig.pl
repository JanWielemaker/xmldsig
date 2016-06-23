:- use_module(xmldsig).
:- use_module('../c14n2/c14n2').

dom('some text\n  with spaces and CR-LF.').

c14n(C14N) :-
	dom(DOM),
	xmldsig:object_c14n(DOM, _ODOM, C14N).

digest(Hash) :-
	dom(DOM),
	xmldsig:dom_hash(DOM, _ODOM, Hash, []).

signedinfo(Signature) :-
	key_options(Options, []),
	digest(Hash),
	xmldsig:signed_info(Hash, Signature, _SDOM, _KeyDOM, Options).

key_options([ key_file('example/AlicePrivRSASign_epk.pem'),
	      key_password("password")
	    | Options
	    ],
	    Options).

rsa_signature(Data, Signature) :-
	key_options(Options, []),
	xmldsig:rsa_signature(Data, Signature, _KeyDOM, Options).

key(Key) :-
	key_options(Options, []),
	xmldsig:private_key(Key, Options).

signed :-
	key_options(Options, []),
	dom(DOM),
	xmld_signed_DOM(DOM, SignedDOM, Options),
	xml_write(current_output, SignedDOM,
		  [layout(false)]).
