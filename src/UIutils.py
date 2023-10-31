import textwrap
import os
from src.ACCOUNTutils import *
from src.MATHutils import *

import subprocess

def execute(command):
    arch = subprocess.check_call(command, shell=True, stdout=sys.stdout, stderr=subprocess.STDOUT)
    return arch
def UI_any_key():
    # For Windows
    if os.name == 'nt':
        os.system("pause")
    else:
        os.system('read -s -n 1 -p "Press any key to continue..."')
def UI_intro(app_name, description, width=60):
    wrapper = textwrap.TextWrapper(width=width)
    word_list = wrapper.wrap(text=description)
    formatted_description = "\n\t".join(word_list)

    separator = "-" * width

    intro_message = f"""
    {separator}
    {app_name.center(width)}  
    {separator}
    \t{formatted_description}
    {separator}
    """
    print(intro_message)
def UI_message(message, width=60):
    wrapper = textwrap.TextWrapper(width=width)
    word_list = wrapper.wrap(text=message)
    formatted_description = "\n\t".join(word_list)

    separator = "-" * width

    message = f"""
    {separator}
    \t{formatted_description}
    {separator}
    """
    print(message)
def UI_options(options_table):
    options = list(options_table.keys())
    print("\tPlease choose one of the following options:")

    for number, option in enumerate(options, 1):
        print(f"\t\t{number}. {option}")

    choice_number = int(input("\tEnter the number of your choice: "))

    if 1 <= choice_number <= len(options):
        return options[choice_number - 1]
    else:
        print("Invalid choice. Please select a valid number.")
        return UI_options(options_table)
def python_account():
    message = (
        "How many words do you want?"
    )

    UI_message(message)

    options = {
        '12 words': None,
        '24 words': None
    }

    choice = UI_options(options)

    word_count = int(choice[:2])

    message = (
        "Here are your account details:"
    )

    UI_message(message)
    account = Account(seedType=seedType.RANDOM, word_count=word_count)
    print(red("WARNING: Please use cold-card for this function. Randomly generated addresses here are not safe."))
    account.spillAddresses()

def dice_account():
    message = (
        "How many words do you want?"
    )

    UI_message(message)

    options = {
        '12 words': None,
        '24 words': None
    }

    choice = UI_options(options)

    word_count = int(choice[:2])

    message = (
        "How many dice rolls do you want?"
    )

    UI_message(message)

    print(red("DISCLAIMER: Only use genuine dice rolls here. 50 rolls for 12 words OR 100 rolls for 24 words."))
    diceRoll = str(input("\tEnter your dice rolls: "))

    message = (
        "Here are your account details:"
    )

    UI_message(message)
    account = Account(seedType=seedType.DICE_ROLL, diceRoll = diceRoll, word_count=word_count)
    account.spillAddresses()

def random_seed():
    message = (
        "How will you be randomizing your seed?"
    )

    UI_message(message)

    options = {
        'Python Random (not reccomended)': python_account,
        'Dice Rolls': dice_account,
    }

    choice = UI_options(options)
    UI_action = options.get(choice)

    UI_action()

def import_seed():
    message = (
        "How will you be importing your seed?"
    )

    UI_message(message)

    options = {
        'From Mnemonic': mnemonic_import,
        'From Entropy': entropy_import
    }

    choice = UI_options(options)
    UI_action = options.get(choice)

    UI_action()

def mnemonic_import():
    mnemonic = str(input("\tEnter your mnemonic words: "))

    message = (
        "Here are your account details:"
    )

    UI_message(message)

    account = Account(input=mnemonic, seedType=seedType.MNEMONIC)
    account.spillAddresses()

def entropy_import():
    entropy_hex = str(input("\tEnter your entropy (16 byte hex): "))
    entropy_bytes = bytes.fromhex(entropy_hex)

    message = (
        "Here are your account details:"
    )

    UI_message(message)

    account = Account(input=entropy_bytes, seedType=seedType.ENTROPY)
    account.spillAddresses()


def create_account():
    message = (
        "How will you be generating your seed?"
    )

    UI_message(message)

    options = {
        'Random Seed': random_seed,
        'Import Seed': import_seed
    }

    choice = UI_options(options)
    UI_action = options.get(choice)

    UI_action()

def seed_shamir_recover():
    message = (
        "Recovering mnemonic in 2 of 3 shamir scheme:"
    )

    UI_message(message)
    execute(f"""python -m slip39.recovery""")
    message = (
        green("Copy entropy hash above and import to new account to get mnemonic.")
    )

    UI_message(message)
def seed_xor_recover():
    message = (
        "Recovering mnemonic in 2 of 2 xor scheme:"
    )

    UI_message(message)

    xor1 = str(input("\tEnter your 12 words (LIST A) for xor recovery: "))
    xor2 = str(input("\tEnter your 12 words (LIST B) for xor recovery: "))

    if (len(xor1.split()) == len(xor2.split())):
        pass
    else:
        print(red("ERROR: Mnemonics are not the same length."))
        return seed_xor_recover()

    xor1_indicies = mnemonic_to_indices(xor1).split()
    xor2_indicies = mnemonic_to_indices(xor2).split()
    xor_indicies = [None for index in xor1_indicies]

    for i in range(len(xor1_indicies)):
         xor_indicies[i] = str(int(xor1_indicies[i])^int(xor2_indicies[i])).zfill(4)

    # Sloppy re-converting mnemonic but oh well. It seems to find the solution!
    mnemonic = indices_to_mnemonic(" ".join(xor_indicies))

    # Extract correct checksum word.
    entropyHash = mnemonic_to_entropyHash(mnemonic)
    mnemonic = get_mnemonic(entropyHash, len(mnemonic.split()))

    account = Account(input=mnemonic, seedType=seedType.MNEMONIC)
    account.spillMnemonic()
    message = (
        green("Please find mnemonic and entropy hash above.")
    )

    UI_message(message)
def seed_bc_recover():

    message = (
        "Seed BC recovery option."
    )

    UI_message(message)

    hashed_transactions_list = []

    done = False
    transaction_count = 1
    while not done:
        entry = str(input(f"\tEnter bc transaction {transaction_count} (to decrypt) (or OK to finish): "))
        isValid = (len(entry) == 10) and (entry[0] == '0') and (entry[1] == '.') and (is_int(entry[2:]))
        if entry == "OK":
            done = True
        elif isValid:
            hashed_transactions_list.append(entry)
        else:
            print(red("ERROR: Invalid Input. "))
            seed_bc_recover()
        transaction_count += 1

    passphrase = str(input("\tPlease enter your passphrase: "))

    wordList_hashed = generate_hashed_bip39(passphrase)

    hashed_mnemonic = hash_transactions_to_hashed_mnemonic(hashed_transactions_list)

    mnemonic = decode_hashed_mnemonic(hashed_mnemonic, wordList_hashed)

    account = Account(input=mnemonic, seedType=seedType.MNEMONIC)
    account.spillMnemonic()
def recover_seed():
    message = (
        "How will you be recovering your seed?"
    )

    UI_message(message)

    options = {
        'Seed Shamir': seed_shamir_recover,
        'Seed XOR': seed_xor_recover,
        'Seed BC': seed_bc_recover
    }

    choice = UI_options(options)
    UI_action = options.get(choice)

    UI_action()
def seed_shamir():
    mnemonic = str(input("\tEnter your 12 words for shamir splitting: "))

    message = (
        "Splitting mnemonic in 2 of 3 shamir scheme:"
    )

    UI_message(message)
    account = Account(input=mnemonic, seedType=seedType.MNEMONIC)
    os.system(f"""python -m slip39 --using-bip39 --secret "{account.entropyHash.hex()}" -c "BTC:m/44'/0'/0'/0/0" -g Shamir(2/3)""")

def seed_xor():
    print(red("ERROR: Please use cold-card to do 2 of 2 with TRNG for this function."))

def seed_bc():
    mnemonic = str(input("\tEnter your 12 words for seed bc writing: "))

    if (len(mnemonic.split()) == 12):
        if (validate_mnemonic(mnemonic)):
            pass
        else:
            print(red("ERROR: NOT A VALID MNEMONIC"))
            seed_bc()
        pass
    else:
        print(red("ERROR: NOT A VALID MNEMONIC"))
        seed_bc()

    passphrase = str(input("\tPlease enter your passphrase: "))

    message = (
        "Encrypting mnemonic in transactions writable to bc"
    )
    UI_message(message)

    hashed_mnemonic_list = generate_hashed_mnemonic(mnemonic, passphrase)

    datalog_hash_transactions(hashed_mnemonic_list)

def backup_seed():
    message = (
        "How will you be backing up your seed?"
    )

    UI_message(message)

    options = {
        'Seed Shamir': seed_shamir,
        'Seed XOR': seed_xor,
        'Seed BC': seed_bc
    }

    choice = UI_options(options)
    UI_action = options.get(choice)

    UI_action()

def UI():
    app_name = "Crypto Utils"
    description = (
        "Welcome to CryptoUtils by TinyDice! Your one-stop script  "
        "for various bitcoin wallet verification, backup and recovery tools. "
        "Follow the prompts to create, verify, backup or recover a bitcoin wallet. "
        "Please run this on an air-gapped computer if handling private keys containing "
        "significant funds."

    )

    UI_intro(app_name, description)

    UI_any_key()

    message = (
        "What will you be needing my assistance with today?"
    )

    UI_message(message)

    options = {
        'Backup Seed': backup_seed,
        'Recover Seed': recover_seed,
        'Create or Verify Account': create_account
    }

    choice = UI_options(options)
    UI_action = options.get(choice)

    UI_action()