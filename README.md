# (README IS OUT OF DATE) Bitcoin Wallet Generator (FOR VERIFICATION AND TESTING PURPOSES ONLY)

This Python script generates bitcoin wallets from a mnemonic (or cold-card dice-roll) and derived addresses based on the provided input.

## Installation

1. Clone the repository.
2. Run main.py and install packages that cause 'missing module' errors:

 	pip install \<missing-package\>
  
    * 2b. Install the required libraries by running the following command (I have not tested this yet):

        * pip install --no-index --find-links -r requirements.txt

## Usage

1. Read the warnings.
2. Fill out config.json
    * input: 
        * Mnemonic "inhale anger power ... " (bip39 compliant string with spaces between each word)
        * Dice roll (cold-card). Eg. "0123456". (string of integers 0-9)
        * Blank (random paper wallet). Eg. "".
    * word_count: Set the number of words in your mnemonic (or how many you want). Eg. 12 or 24. (positive integer)
        * This value is only used for dice-roll or blank inputs. 
    * passphrase: Set your string password (13th/25th mnemonic word). Eg. "PASSWORD123" (any string)
    * wallet_types: Set wallet type (public key type). Eg. "BIP44" (Legacy) or "BIP49" (P2WPKH) or "BIP84" (bech32 segwit). (string)
    * gap_limit: Set how many deposit and change addresses you want to see (each). Eg. 5 or 10 or 11 or 1000. (any positive integer)
    * is_private: Set True if you do NOT want to print the private key WIF. (boolean)
 
3. Run main.py
       
## WARNINGS
1. input:
    * If you enter a mnemonic. DO NOT run this script on a device that has been or will ever connect to the internet. (Unless you are willing to lose all funds). 
    * If you enter a blank input. DO NOT use any wallet derived to store funds (Unless you are willing to lose all funds).
2. wallet_types: While the same public key is used to derive all three deposit address formats availible in this code - each deposit address format is to be considered a unique wallet.  
3. is_private:
    * Since private key WIFs are still calculated (and just not printed if is_private = True). Do not think of this as a security feature - input warnigns still apply.
4. I am not legally responsible for the loss of funds resulting in the misuse of any python code in this repository. 
