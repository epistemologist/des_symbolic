from des import DES
from tqdm import tqdm
from functools import reduce
from parse import CNF_Form
from subprocess import PIPE, Popen
import random, sys, z3, re

random.seed(42)

z3.set_option(verbose=19)
z3.set_param('parallel.enable', True)

ROUNDS = 6
NUM_PAIRS = 5
NUM_KNOWN_KEY_BITS = 20
NUM_THREADS = 4

SOLVER = "BOSPHORUS"

BOSPHORUS_BIN_PATH = "/opt/bosphorus/build/bosphorus"
CRYPTOMINISAT_BIN_PATH = "/opt/cryptominisat/build/cryptominisat5"

KNOWN_BITS = set(random.sample([i for i in range(64) if i % 8 != 0], NUM_KNOWN_KEY_BITS))

def gen_random_des_key():
    def _popcnt(x): return bin(x).count('1')
    key_bits = [random.randint(0, 128-1) for i in range(8)]
    key_bytes = [k << 1 | b for k, b in zip(
        key_bits, [(_popcnt(i) + 1) % 2 for i in key_bits])]
    return reduce(lambda x, y: x | y, [i << (8*n) for n, i in enumerate(key_bytes)])

k_hidden = gen_random_des_key()
cipher = DES(key=k_hidden, rounds=ROUNDS)

pt_vals = [random.randint(0, 2**64) for i in range(NUM_PAIRS)]
ct_vals = [cipher.encrypt(i) for i in pt_vals]

k = z3.BitVec("k", 64)

goal = z3.Goal()

key_vars = [z3.Bool(f"k_{i}") for i in range(64)]
key_var_str_to_var = {str(v): v for v in key_vars}
key_known_bits = dict()

# Add Boolean variables to access each bit of the key
for i in range(64):
	goal.add((z3.Extract(i,i,k) == 1) == key_vars[i])
	if i in KNOWN_BITS: 
		goal.add(key_vars[i] == (z3.Extract(i,i,z3.BitVecVal(k_hidden, 64)) == 1))
		key_known_bits[key_vars[i]] = int(k_hidden & (1 << i) != 0)

print("Known bits: ", key_known_bits)

# Add conditions that each byte of key must have odd parity
for i in range(0, 64, 8):
	goal.add(reduce(z3.Xor, [key_vars[i+j] for j in range(8)]))

print("Adding conditions for encryption...")
for pt, ct in tqdm(zip(pt_vals, ct_vals)):
    p = z3.BitVecVal(pt, 64)
    c = z3.BitVecVal(ct, 64)
    goal.add(DES(key=k, rounds=ROUNDS).encrypt(p) == c)


subgoal = z3.Then(z3.With('simplify', mul2concat=True),
                  'solve-eqs', 'bit-blast', 'aig', 'tseitin-cnf')(goal)
s_expr = subgoal.as_expr().sexpr()

key_vars_used = [key_vars[i] for i in range(len(key_vars)) if i not in KNOWN_BITS]

cnf = CNF_Form(sexpr_str=s_expr)
print(f"cnf: {cnf}")
f = open("tmp.cnf", "w")
f.write(cnf.to_dimacs())
f.close()

to_int = lambda bit_arr: sum([bit << i for i, bit in enumerate(bit_arr)])

def reconstruct_key():
	found_key_vars = [key_var_str_to_var[v_str] for v_str in set(sol_var_map.keys()) & set([str(i) for i in key_vars])]
	for v in found_key_vars:
		key_known_bits[v] = sol_var_map[str(v)]
	s = z3.Solver()
	s.add(goal.as_expr())
	for v, val in key_known_bits.items():
		s.add(v == bool(val))
	assert s.check() == z3.sat
	return s.model().evaluate(k).as_long()

if SOLVER == "Z3":
	s = z3.Solver()
	s.add(goal.as_expr())
	assert s.check() == z3.sat
	key_found = s.model().evaluate(k).as_long()

elif SOLVER == "CRYPTOMINISAT":
	# Get missing bits with Cryptominisat
	process = Popen(f"{CRYPTOMINISAT_BIN_PATH} --verb 5 -t {NUM_THREADS} --dumpresult out.sol tmp.cnf".split(), stdin=PIPE, stdout = sys.stdout.buffer)
	process.wait()

	sol = set(re.findall("-?[0-9]+", open("out.sol", "r").readlines()[-1]))
	sol_var_map = {
		v: int(str(i+1) in sol) for i, v in enumerate(cnf.variables)
	}
	# Reconstruct key with z3
	key_found = reconstruct_key() 
elif SOLVER == "BOSPHORUS":
	# Use Bosphorus to solve for unknown bits
	process = Popen(f"{BOSPHORUS_BIN_PATH} --cnfread tmp.cnf --solve --solvewrite out.sol -v 3 --maxtime 3600".split(), stdin = PIPE, stdout = sys.stdout.buffer)
	process.wait()

	# Take only the first solution
	sol_text = open("out.sol", "r").readlines()
	sol = [set(re.findall("-?[0-9]+", line)) for line in sol_text if line.startswith("v")][0]

	sol_var_map = {v: int(str(i) in sol) for i, v in enumerate(cnf.variables)}
	key_found = reconstruct_key()

else:
	raise ValueError("invalid solver!")

print(f"Key found: {key_found}")
print(f"Actual key: {k_hidden}")
assert all([DES(key=key_found, rounds=ROUNDS).encrypt(p) == c for p,c in zip(pt_vals, ct_vals)])
