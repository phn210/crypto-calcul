from rng_wrapper import RNG

rng = RNG()
base = 16
rand = rng.rand_int_b(1024, base)
print(rand)
print(int(rand, base))