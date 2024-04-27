import shamir_mnemonic as shamir
from src.ACCOUNTutils import *
import random
from shamir_mnemonic import shamir
def random_bytes(n):
    return bytes(random.randrange(256) for _ in range(n))

shamir.RANDOM_BYTES = random_bytes
def main():
    mnemonic = "also play glass milk marriage wine crucial blast whale year crime trap"
    account_in = Account(input=mnemonic, seedType=seedType.MNEMONIC, word_count=12)
    print(account_in.mnemonic)
    secret = account_in.entropyHash
    shamir_mnemonics = shamir.generate_mnemonics(member_threshold=2, member_count=3, master_secret=secret, passphrase="", iteration_exponent=5)
    test_mnemonic_indexes = random.sample([0,1,2], 2)
    entropyHash = shamir.combine_mnemonics([shamir_mnemonics[test_mnemonic_indexes[0]], shamir_mnemonics[test_mnemonic_indexes[1]]], b"")
    account_out = Account(input=entropyHash, seedType=seedType.ENTROPY, word_count=12)
    print(account_out.mnemonic)

if __name__ == "__main__":
    main()