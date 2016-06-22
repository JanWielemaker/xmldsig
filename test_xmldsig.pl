:- use_module(xmldsig).

dom('some text\n  with spaces and CR-LF.').

c14n(C14N) :-
	dom(DOM),
	xmldsig:object_c14n(DOM, C14N).

digest(Hash) :-
	dom(DOM),
	xmldsig:dom_hash(DOM, Hash, []).

signedinfo(Signature) :-
	key_options(Options, []),
	digest(Hash),
	xmldsig:signed_info(Hash, Signature, _SDOM, Options).

key_options([ key_file('example/AlicePrivRSASign_epk.pem'),
	      key_password("password")
	    | Options
	    ],
	    Options).

rsa_signature(Data, Signature) :-
	key_options(Options, []),
	xmldsig:rsa_signature(Data, Signature, Options).
