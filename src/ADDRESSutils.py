from .FORMATutils import *
from .COLORutils import green, red

class Address:
    def __init__(self, root_xprv, path, addressType):
        self.path = path
        self.addressType = addressType
        self.root_xprv = root_xprv
        self.derived_addr_prv = self.root_xprv.derive_child_xprv(convert_path(self.path))
        self.derived_addr_pub = self.derived_addr_prv.derive_pubkey()
        self.private_key = self.derived_addr_prv.key
        self.wif = bytes_priv_to_wif(self.private_key)
        self.public_key = self.derived_addr_pub.key

        if (self.addressType == "P2PKH"):
            self.address = pubkey_to_P2PKH(self.public_key)
            self.verifyResult = green("✔") if (wif_to_P2PKH(self.wif) == self.address) else red("X")
        elif (self.addressType == 'P2WPKH'):
            self.address = pubkey_to_P2SHpP2WPKH(self.public_key)
            self.verifyResult = green("✔") if (wif_to_P2SHpP2WPKH(self.wif) == self.address) else red("X")
        elif (self.addressType == 'bech32'):
            self.address = pubkey_to_bech32(self.public_key)
            self.verifyResult = green("✔") if (wif_to_bech32(self.wif) == self.address) else red("X")

    def spill_address(self, isPrivate=False):  # Added self
        if isPrivate:
            print(f'    {self.path}     {self.address}     {self.verifyResult}')
        else:
            print(f'    {self.path}     {self.address}     {self.wif}     {self.verifyResult}')