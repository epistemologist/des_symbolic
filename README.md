# Symbolic Description of DES

Here is an implementation of DES that also uses z3 - this allows for the algebraic conditions of the cipher to be encoded to be solved with other tools. See `example.py` for an example.

# TODO
 - rewrite this README
 - add other ciphers
 - try to break more than 6 rounds of DES with just SAT (after 6 rounds, there are no more linear relations between input and output bits so problem becomes harder)
 - look into other tools
