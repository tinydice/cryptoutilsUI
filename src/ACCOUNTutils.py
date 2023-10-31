import os
import json
from enum import Enum
from .WALLETutils import *
from .BIP32utils import *
from .BIP39utils import *

class seedType(Enum):
    MNEMONIC = 1
    ENTROPY = 2
    DICE_ROLL = 3
    RANDOM = 4

BIP44_PATH = "m/44'/0'/0'"
BIP49_PATH = "m/49'/0'/0'"
BIP84_PATH = "m/84'/0'/0'"

COMMON_PATHS = [BIP44_PATH, BIP49_PATH, BIP84_PATH]

class Account:
    def __init__(self, input="", passphrase="", seedType=seedType.MNEMONIC, diceRoll="666", word_count=12, walletTypes="BIP44"):

        self.input = input
        self.word_count = word_count
        self.passphrase = passphrase
        self.walletTypes = walletTypes
        self.walletTypes = [self.walletTypes] if isinstance(self.walletTypes, str) else self.walletTypes
        self.seedType = seedType
        self.gapLimit = 3

        if (self.seedType == seedType.MNEMONIC):
            self.entropyHash = mnemonic_to_entropyHash(self.input)
            self.mnemonic = get_mnemonic(self.entropyHash, self.word_count)
            if (self.mnemonic != self.input):
                print(f'{red("ERROR: INVALID MNEMONIC")}')
        elif (self.seedType == seedType.RANDOM):
            randints_77 = []
            for _ in range(77):
                randint = int.from_bytes(os.urandom(1), "big") % 10 + 1
                randints_77.append(str(randint))
            self.randints_77 = ''.join(randints_77)
            self.entropyHash = sha256(self.randints_77.encode("utf-8"))
            self.mnemonic = get_mnemonic(self.entropyHash, self.word_count)
        elif (self.seedType == seedType.DICE_ROLL):
            self.diceRoll = diceRoll
            self.entropyHash = sha256(self.diceRoll.encode("utf-8"))
            self.mnemonic = get_mnemonic(self.entropyHash, self.word_count)
        elif (self.seedType == seedType.ENTROPY):
            self.entropyHash = self.input
            self.mnemonic = get_mnemonic(self.entropyHash, self.word_count)

        self.mnemonic_indicies = mnemonic_to_indices(self.mnemonic)
        self.mnemonic_indicies_hex = mnemonic_to_indices(self.mnemonic, True)
        self.wallets = []

        for walletType in self.walletTypes:
            if (walletType == 'BIP44'):
                self.path = BIP44_PATH
                self.addressType = 'P2PKH'
            elif (walletType == 'BIP49'):
                self.path = BIP49_PATH
                self.addressType = 'P2WPKH'
            elif (walletType == 'BIP84'):
                self.path = BIP84_PATH
                self.addressType = 'bech32'

            self.seed = get_seed(self.mnemonic.encode('utf-8'), self.passphrase)
            self.root_xprv = extendedKey.parse_from_seed(self.seed)
            self.xprv = self.root_xprv.derive_child_xprv(convert_path(self.path))
            self.derived_addr_prv = self.root_xprv.derive_child_xprv(convert_path(self.path))
            self.xpub = self.derived_addr_prv.derive_pubkey()

            self.wallets.append(Wallet(self.root_xprv, self.addressType, self.path, self.gapLimit))

    def spillAddresses(self):
        if (self.passphrase != ''):
            print(f'Passphrase:')
            print(f"    {self.passphrase}")
        if (validate_mnemonic(self.mnemonic)):
            self.verifyResult = green("✔")
        else:
            self.verifyResult = red("X")
        print(f'Entropy:')
        print(f"    {blue(self.entropyHash.hex())}     {self.verifyResult}")
        print(f'Mnemonic:')
        print(f"    {green(self.mnemonic)} {self.passphrase}     {self.verifyResult}")
        self.verifyResult = green("✔") if (indices_to_mnemonic(self.mnemonic_indicies) == self.mnemonic) else red("X")
        print(f'Indicies:')
        print(f'    Numeric: {self.mnemonic_indicies}     {self.verifyResult}')
        self.verifyResult = green("✔") if (indices_to_mnemonic(self.mnemonic_indicies_hex, True) == self.mnemonic) else red("X")
        print(f'    Hex:     {self.mnemonic_indicies_hex}     {self.verifyResult}')
        print(f'XPRV:')
        print(f"    {self.xprv.serialize()}")
        print(f'XPUB:')
        print(f"    {self.xpub.serialize()}")
        for i in range(len(self.wallets)) :
            wallet_type = self.walletTypes[i]
            print(f'Addresses:         ({wallet_type})')
            for address in self.wallets[i].addresses:
                address.spill_address(False)
            print(f'Change Addresses:  ({wallet_type})')
            for changeAddress in self.wallets[i].changeAddresses:
                changeAddress.spill_address(False)
    def spillMnemonic(self):
        if (validate_mnemonic(self.mnemonic)):
            self.verifyResult = green("✔")
        else:
            self.verifyResult = red("X")
        print(f'Entropy:')
        print(f"    {blue(self.entropyHash.hex())}     {self.verifyResult}")
        print(f'Mnemonic:')
        print(f"    {green(self.mnemonic)} {self.passphrase}     {self.verifyResult}")
        self.verifyResult = green("✔") if (indices_to_mnemonic(self.mnemonic_indicies) == self.mnemonic) else red("X")
