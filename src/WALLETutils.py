from .ADDRESSutils import *

class Wallet:
    def __init__(self, seed, addressType, path, gapLimit):
        self.seed = seed
        self.addressType = addressType

        self.addressPaths = []
        self.changeAddressPaths = []

        self.addresses = []
        self.changeAddresses = []
        for addressNum in range(gapLimit):
            self.addressPaths.append(path+ '/0/'+str(addressNum))
            self.changeAddressPaths.append(path+'/1/'+str(addressNum))
        self.path = path

        self.addresses = []
        for i in range(gapLimit):
            self.addresses.append(Address(self.seed, self.addressPaths[i], self.addressType))
            self.changeAddresses.append(Address(self.seed, self.changeAddressPaths[i], self.addressType))