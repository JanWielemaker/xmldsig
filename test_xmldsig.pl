:- use_module(xmldsig).

dom('some text\n  with spaces and CR-LF.').

c14n(C14N) :-
	dom(DOM),
	xmldsig:object_c14n(DOM, C14N).

digest(Hash) :-
	dom(DOM),
	xmldsig:dom_hash(DOM, Hash, []).
