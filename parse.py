import z3, sexpdata, re
from dataclasses import dataclass
from tqdm import tqdm
from math import prod
from typing import List, Optional
from bisect import bisect_left
from itertools import groupby
from functools import reduce
from subprocess import Popen, PIPE


# Hacky way to include sage
try:
    import sys
    sys.path.append('/usr/lib/python3/dist-packages/')

    from sage.all import var, BooleanPolynomialRing
except:
    pass

@dataclass
class Symbol:
	name: str
	inverted: bool

Clause = List[Symbol]

@dataclass
class CNF_Form:
	variables: Optional[List[str]] = None
	clauses: Optional[List[Clause]] = None

	def __init__(self, variables = None, clauses = None, sexpr_str: Optional[str]=None, verbose=False):
		self.progress_bar = tqdm if verbose else (lambda x: x)
		if sexpr_str is not None:
			self.variables, self.clauses = self.construct_from_sexpr_str(sexpr_str, progress_bar =self.progress_bar)
		else:
			# TODO: To implement - might be worth to add some more checks than just default constructor here
			self.variables, self.clauses = variables, clauses

	def __repr__(self):
		return f"CNF object with {len(self.clauses)} clauses in {len(self.variables)} variables"

	@staticmethod
	# Converts sexpr string (from a z3 model for example) into CNF form
	def construct_from_sexpr_str(sexpr_str: str, progress_bar = tqdm):
		parsed_data = sexpdata.loads(sexpr_str)
		# Check that this is actually CNF
		def _construct_clause(clause):
			if type(clause) == sexpdata.Symbol:
				return [Symbol(name=str(clause), inverted=False)]
			if type(clause) == list:
				if len(clause) == 2 and clause[0] == sexpdata.Symbol('not'):
					return [Symbol(name=str(clause[1]), inverted=True)]
				if clause[0] == sexpdata.Symbol('or'):
					or_args = []
					for arg in clause[1:]:
						if type(arg) == sexpdata.Symbol:
							or_args.append(Symbol(name=str(arg), inverted=False))
						elif type(arg) == list and len(arg) == 2 and arg[0] == sexpdata.Symbol('not'):
							or_args.append(Symbol(name = str(arg[1]), inverted=True ))
						else:
							 break
					return or_args
			raise ValueError(f"invalid clause! {clause} of type {type(clause)}")
		clauses = [_construct_clause(clause) for clause in progress_bar(parsed_data[1:])]
		variables = sorted({i.name for clause in clauses for i in clause})
		return variables, clauses

	def to_dimacs(self) -> str:
		str_out = ""
		str_out += f"p cnf {len(self.variables)} {len(self.clauses)}" + "\n"
		def _get_var_index(v):
			return (-1 if v.inverted else 1) * (bisect_left(self.variables, v.name) + 1)
		for clause in self.progress_bar(self.clauses):
			str_out += " ".join([str(_get_var_index(v)) for v in clause]) + " 0\n"
		return str_out.rstrip()

	# To get solutions from cnf:
	# ./cryptominisat/build/cryptominisat5_simple < out.cnf | grep "^v" | grep -oE "\-?[0-9]+" | tr '\n' ','; echo
	def process_sols_from_sat(self, sols):
		sol_dict = dict()
		for i in sols:
			if i != 0: sol_dict[self.variables[abs(i) - 1]] = (i > 0)
		# By convention, we represent bit vectors as p = (p_0, p_1, p_2, ..., p_n)
		bitvec_vars = [ v for v in self.variables if re.match("[a-z]+_[0-9]+", v)]
		# Group by the bitvector
		for k, g in groupby(bitvec_vars, key = lambda s: s.split("_")[0]):
			curr_bitvec_bits = sorted([ (int(i.split("_")[-1]), sol_dict[i]) for i in g])
			bitvec = reduce(lambda x,y: x|y, [1<<i for i, bit in curr_bitvec_bits if bit])
			print(k, bitvec)
		return sol_dict

@dataclass
class ANF_Form:

#	parent_ring:
#	eqns: List[]

	def __init__(self):
		pass


"""
def cnf_to_anf(cnf_string):
	conds = [line.strip() for line in cnf_string.splitlines()]
	variables, conds = conds[0].split()[-1].split(","), [[int(i)
														  for i in c.split()][:-1] for c in conds[2:]]
	to_sage = dict()
	for i in variables:
		if "k!" in str(i):
			to_sage[i] = str(i).replace("k!", "a")
		else:
			to_sage[i] = i
	variables = [None] + [var(to_sage[i]) for i in variables]
	poly_sym = []
	for cond in tqdm(conds):
		poly_sym.append(
			1+prod([variables[-i] if i < 0 else (1+variables[i]) for i in cond]))
	variables = variables[1:]
	R = BooleanPolynomialRing(names = [str(i) for i in list(to_sage.values())], order='lex')
	polys = [p.polynomial(ring=R) for p in tqdm(poly_sym)]
	return R, polys
"""
