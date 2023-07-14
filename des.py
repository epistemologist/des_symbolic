import z3
from collections import defaultdict
from functools import reduce
from tqdm import tqdm

# Consts

PC_1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44,
        36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
KEY_SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
PC_2 = [14, 17, 11, 24,  1,  5, 3, 28, 15,  6, 21, 10, 23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,
        2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16,
      8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
IP_INV = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61,
          29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]


E = [32, 1,  2,  3,  4,  5, 4,  5,  6,  7,  8,  9, 8,  9,  10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31,
     10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

# Set up S boxes
Sboxes_raw = {
    0: (
        14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
        0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
        4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
        15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
    ),
    1: (
        15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
        3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
        0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
        13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
    ),
    2: (
        10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
        13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
        13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
        1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
    ),
    3: (
        7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
        13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
        10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
        3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
    ),
    4: (
        2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
        14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
        4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
        11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
    ),
    5: (
        12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
        10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
        9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
        4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
    ),
    6: (
        4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
        13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
        1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
        6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
    ),
    7: (
        13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
        1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
        7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
        2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
    )
}

DES_S_BOXES = dict()
for i, S in Sboxes_raw.items():
    new_S_box = defaultdict(int)
    for j in range(64):
        row_num = ((j & (1 << 5)) >> 4 | (j & 1))
        col_num = (j & 0b11110) >> 1
        new_S_box[j] = S[16*row_num + col_num]
    DES_S_BOXES[i] = [new_S_box[j] for j in range(64)]


# To deal with z3 and arithmetic shifts
def rshift(N, shift):
    if type(N) == int:
        return N >> shift
    else:
        return z3.LShR(N, shift)


def ROTL(N, k, LENGTH):
    k %= LENGTH
    return ((N << k) | rshift(N, (LENGTH - k))) & ((1 << LENGTH)-1)


def ROTR(N, k, LENGTH):
    k %= LENGTH
    return (rshift(N, k) | (N << (LENGTH - k))) & ((1 << LENGTH)-1)


def resize_bitvec(bit_vec, new_size):
    if type(bit_vec) != int:
        curr_size = bit_vec.size()
        if new_size > curr_size:
            return z3.ZeroExt(new_size - curr_size, bit_vec)
        else:
            return z3.Extract(new_size-1, 0, bit_vec)
    else:
        return bit_vec


def simplify(bit_vec):
    return bit_vec if type(bit_vec) == int else z3.simplify(bit_vec)


def apply_bit_permutation(bit_vec, len_in, len_out, permutation):
    def get_bit(N, bit): return rshift((N & (1 << bit)), bit)
    def set_bit(N, bit, val): return N | (val << bit)
    bit_vec = resize_bitvec(bit_vec, max(len_in, len_out))
    out = 0
    for i in range(len(permutation)):
        out = set_bit(out, len_out-i-1,
                      get_bit(bit_vec, len_in - (permutation[i])))
    return resize_bitvec(out, len_out)


class DES:
    def __init__(self, key, rounds=16, Sboxes=DES_S_BOXES):
        self.key = key
        self.round_keys = self.get_round_keys(key)
        self.rounds = rounds
        self.Sboxes = Sboxes

    # Returns symbolic expression for putting in 48 bits -> 32 bit S box
    def substitute(self, bit_vec_in):
        if type(bit_vec_in) == int:
            return reduce(lambda a, b: a | b, [self.Sboxes[7-i][(bit_vec_in & (0b111111 << (6*i))) >> (6*i)] << (4*i) for i in reversed(range(8))])
        else:
            def _construct_if(index, arr):
                expr = z3.If(index == 0, z3.BitVecVal(arr[0], 4), False)
                for i in range(1, len(arr)):
                    expr = z3.If(index == i, z3.BitVecVal(arr[i], 4), expr)
                return expr
            idx_arr = [z3.Extract(6*i+5, 6*i, bit_vec_in)
                       for i in reversed(range(8))]
            return z3.Concat([_construct_if(idx, self.Sboxes[i]) for i, idx in enumerate(idx_arr)])

    def get_round_keys(self, key):
        key = apply_bit_permutation(key, 64, 56, PC_1)
        left = resize_bitvec(rshift(key, 28) & 0xFFFFFFF, 28)
        right = resize_bitvec((key & 0xFFFFFFF), 28)
        round_keys = []
        for shift in KEY_SHIFT:
            right = ROTL(right, shift, 28)
            left = ROTL(left, shift, 28)
            concat = resize_bitvec(left, 56) << 28 | resize_bitvec(right, 56)
            round_keys.append(apply_bit_permutation(concat, 56, 48, PC_2))
        return round_keys

    def encrypt(self, pt):
        pt = apply_bit_permutation(pt, 64, 64, IP)
        left = resize_bitvec(rshift(pt, 32), 32)
        right = resize_bitvec(pt & 0xFFFFFFFF, 32)
        (left, right) = self.feistel(left, right, range(self.rounds))
        concat = resize_bitvec(right, 64) << 32 | resize_bitvec(left, 64)
        return apply_bit_permutation(concat, 64, 64, IP_INV)

    def decrypt(self, pt):
        pt = apply_bit_permutation(pt, 64, 64, IP)
        left = resize_bitvec(rshift(pt, 32), 32)
        right = resize_bitvec(pt & 0xFFFFFFFF, 32)
        (left, right) = self.feistel(left, right, reversed(range(self.rounds)))
        concat = resize_bitvec(right, 64) << 32 | resize_bitvec(left, 64)
        return apply_bit_permutation(concat, 64, 64, IP_INV)

    def feistel(self, left, right, subkey_idx):
        for i in subkey_idx:
            tmp = right
            right = apply_bit_permutation(right, 32, 48, E)
            right = right ^ self.round_keys[i]
            right = self.substitute(right)
            right = apply_bit_permutation(right, 32, 32, P)
            right = right ^ left
            left = tmp
        return (left, right)

    def gen_sexpr(self, pts=None, cts=None, verbose=False):
        if type(self.key) == int:
            raise AssertionError("Cipher is not symbolic!")
        if verbose:
            z3.set_option("verbose", 19)
        goal = z3.Goal()
        # Add conditions for each key bit
        for i in range(64):
            goal.add((z3.Extract(i, i, self.key) == 1) == z3.Bool("k_%02d" % i))
        # Add parity condition for key
        for i in range(0, 64, 8):
            goal.add(
                reduce(z3.Xor, [z3.Extract(i+j, i+j, self.key) == 1 for j in range(8)]))
        if pts is None and cts is None:
            pt = z3.BitVec("p", 64)
            ct = z3.BitVec("c", 64)
            for i in range(0, 64):
                goal.add((z3.Extract(i, i, pt) == 1) == z3.Bool("p_%02d" % i))
                goal.add((z3.Extract(i, i, ct) == 1) == z3.Bool("c_%02d" % i))
            goal.add(self.encrypt(pt) == ct)
        else:
            for pt, ct in zip(pts, cts):
                goal.add(self.encrypt(z3.BitVecVal(pt, 64))
                         == z3.BitVecVal(ct, 64))

        bv_to_cnf_tactic = z3.Then(z3.With('simplify', mul2concat=True),
                                   'propagate-values',
                                   'solve-eqs',
                                   'bit-blast',
                                   'aig',
                                   'tseitin-cnf')
        return bv_to_cnf_tactic(goal).as_expr().sexpr()

# Test code


def sanity_tests():
    # https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
    assert DES(key=0x133457799BBCDFF1).round_keys == [29699430183026,
                                                      133791886330341,
                                                      94543139753881,
                                                      126090959598877,
                                                      137353186988968,
                                                      109561366215471,
                                                      260054766196924,
                                                      272173063289851,
                                                      247235160696705,
                                                      195658438559311,
                                                      36695460205446,
                                                      129132311898089,
                                                      166875887221313,
                                                      104744453596986,
                                                      210631860764426,
                                                      223465186400245]
    assert DES(key=0x133457799BBCDFF1).encrypt(
        0x0123456789ABCDEF) == 0x85E813540F0AB405
    # http://cryptomanager.com/tv.html
    assert DES(key=0x752878397493CB70).encrypt(
        0x1122334455667788) == 0xB5219EE81AA7499D
    # https://rosettacode.org/wiki/Data_Encryption_Standard
    assert DES(key=0x0e329232ea6d0d73).encrypt(0x8787878787878787) == 0
    assert DES(key=0x0e329232ea6d0d73).decrypt(0) == 0x8787878787878787
