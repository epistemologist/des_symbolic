from des import DES
from functools import reduce
import z3, random

# Example of breaking 2 round DES

z3.set_option(verbose=19)
random.seed(42)

def gen_random_des_key():
    def _popcnt(x): return bin(x).count('1')
    key_bits = [random.randint(0, 128-1) for i in range(8)]
    key_bytes = [k << 1 | b for k, b in zip(
        key_bits, [(_popcnt(i) + 1) % 2 for i in key_bits])]
    return reduce(lambda x, y: x | y, [i << (8*n) for n, i in enumerate(key_bytes)])

# Get random key and generate random pt/ct pairs
k_hidden = gen_random_des_key()
cipher = DES(key = k_hidden, rounds = 2)
pts = [random.randint(0, 2**64-1) for i in range(10)]
cts = [cipher.encrypt(pt) for pt in pts]

# Now use symbolic cipher to generate equivalent conditions for the encryption of pt/ct pairs
# and use z3 to solve

s = z3.Solver()
k = z3.BitVec("k", 64)

# Add encryption conditions
for pt, ct in zip(pts, cts):
    s.add(DES(key = k, rounds = 2).encrypt(pt) == ct)
# Also add parity conditions for DES key

for i in range(0, 64, 8):
	s.add(reduce(z3.Xor, [z3.Extract(i+j, i+j, k) == 1 for j in range(8)]))

assert s.check() == z3.sat
print(f"Key found: {s.model().evaluate(k).as_long()}")
print(f"Actual key: {k_hidden}")
