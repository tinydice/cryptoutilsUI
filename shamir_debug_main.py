from src.ACCOUNTutils import *
import random
from src import shamir


def main():
    mnemonic = "also play glass milk marriage wine crucial blast whale year crime trap"
    account_in = Account(input=mnemonic, seedType=seedType.MNEMONIC, word_count=12)
    print(account_in.mnemonic)
    entropyHash = account_in.entropyHash
    print(int(entropyHash.hex(),16))
    shamir_mnemonics = shamir.generate_mnemonics(member_threshold=2, member_count=3, entropyHash=entropyHash, passphrase="", iteration_exponent=5)
    print("Shamir Mnemonics (2 of 3):")
    for mnemonic in shamir_mnemonics:
        print(f'      {mnemonic}')
    test_mnemonic_indexes = random.sample([0,1,2], 2)
    entropyHash = shamir.combine_mnemonics([shamir_mnemonics[test_mnemonic_indexes[0]], shamir_mnemonics[test_mnemonic_indexes[1]]], b"")
    account_out = Account(input=entropyHash, seedType=seedType.ENTROPY, word_count=12)
    print(account_out.mnemonic)

if __name__ == "__main__":
    main()