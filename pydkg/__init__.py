# # KD
# import pydkg, bitcoin, functools, itertools
# num_participants = 8
# threshold = 5
# poly1 = pydkg.random_polynomial(threshold)
# poly2 = pydkg.random_polynomial(threshold)
# addresses = tuple(pydkg.random.randrange(2**160) for _ in range(num_participants))
# secret_shares1 = tuple(pydkg.eval_polynomial(poly1, addr) for addr in addresses)
# secret_shares2 = tuple(pydkg.eval_polynomial(poly2, addr) for addr in addresses)
# public_shares = tuple(secp256k1.add(secp256k1.multiply(secp256k1.G, a), secp256k1.multiply(pydkg.G2, b)) for a, b in zip(poly1, poly2))
#
# # KV
# verification_lhs = tuple(secp256k1.add(secp256k1.multiply(secp256k1.G, sh1), secp256k1.multiply(pydkg.G2, sh2)) for sh1, sh2 in zip(secret_shares1, secret_shares2))
# verification_rhs = tuple(functools.reduce(secp256k1.add, (secp256k1.multiply(ps, pow(addr, k, secp256k1.N)) for k, ps in enumerate(public_shares))) for addr in addresses)
#
# verification_lhs == verification_rhs
#
# # KC
# # will need network protocol to test
#
# # KG
# public_key_part = secp256k1.multiply(secp256k1.G, poly1[0])
#
# # Lagrangian interpolation test
# secp256k1.multiply(secp256k1.G, tuple(sum(sh * functools.reduce(lambda a,b: a*b%secp256k1.N, (addr2 * pow(addr2 - addr, secp256k1.N-2, secp256k1.N) for (addr2, _) in addr_sh_combos if addr2 != addr)) for (addr, sh) in addr_sh_combos) % secp256k1.N for addr_sh_combos in itertools.combinations(zip(addresses, secret_shares1), threshold))[0]) == public_key_part
