import json
import hashlib
import random
import time
import itertools

"""File format
{
    "assets": {
        "BTC": {
            "usdt_decimals": 0,
            "balance_decimals": 6
        },
        ...
    },
    accounts: {
        "<user_hash>": {
            "BTC": 1,
            ...
        }
    }
}

"""

ledgers_set = {}
assets_set = {}

NUMBER_OF_ASSETS = 10
NUMBER_OF_CUSTOMERS = 2**15

# generate test_assets

def generate_test_assets():
    assets = {}
    asset_names = itertools.permutations("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 3)
    for i in range(NUMBER_OF_ASSETS):
        asset_name = ''.join(asset_names.__next__())
        usdt_decimals = random.randint(0, 6)
        balance_decimals = 6 - usdt_decimals
        price = random.randint(1000, 100000)
        assets[asset_name] = {
            "usdt_decimals": usdt_decimals,
            "balance_decimals": balance_decimals,
            "price": price
        }
    return assets

TEST_ASSETS = generate_test_assets()


def sha256(userid):
    m = hashlib.sha256()
    m.update(userid.encode('utf-8'))
    return m.hexdigest()


def generate_test_data():
    # Generate ledgers
    for i in range(1, NUMBER_OF_CUSTOMERS + 1):
        userid = str(i)
        user_hash = sha256(userid)
        ledgers_set[user_hash] = {}
        for asset, data in TEST_ASSETS.items():
            balance = random.randint(-100, 1000000)
            ledgers_set[user_hash][asset] = balance
            

    # Generate assets
    for asset, data in TEST_ASSETS.items():
        assets_set[asset] = data

    return {"assets": assets_set, "accounts": ledgers_set, "timestamp": int(time.time_ns() // 1_000_000)}

def save_test_data_to_file(test_data, filename='private_ledger.json'):
    with open(filename, 'w') as f:
        json.dump(test_data, f, separators=(',', ':'))
    print(f"Test data saved to {filename}")


if __name__ == "__main__":
    test_data = generate_test_data()
    save_test_data_to_file(test_data)
    print("Test data generation completed.")
