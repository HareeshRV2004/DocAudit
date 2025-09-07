import json
import os
from web3 import Web3

GANACHE_URL = "http://127.0.0.1:7545"  # default Ganache GUI port (use 8545 if truffle develop)

# Load contract ABI + address from Truffle artifact
with open(os.path.join(os.path.dirname(__file__), "build", "contracts", "Verifier.json"), "r", encoding="utf-8") as f:
    contract_json = json.load(f)

CONTRACT_ABI = contract_json["abi"]

# Extract deployed address from networks section
# Assuming you already did "truffle migrate --network development"
network_id = list(contract_json["networks"].keys())[0]  # e.g., "5777"
CONTRACT_ADDRESS = contract_json["networks"][network_id]["address"]


class Blockchain:
    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
        if not self.w3.is_connected():
            raise RuntimeError(f"Cannot connect to Ganache at {GANACHE_URL}")

        # Create contract instance
        self.contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(CONTRACT_ADDRESS),
            abi=CONTRACT_ABI
        )

    def keccak_hex(self, data_bytes: bytes) -> str:
        return self.w3.keccak(data_bytes).hex()

    def set_aadhaar_commitments(self, account, private_key, commitment_id_hex,
                                above18_hex, indian_hex, gender_hex,
                                name_hash_hex, validity_hex):
        nonce = self.w3.eth.get_transaction_count(account)
        tx = self.contract.functions.setAadhaarCommitments(
            Web3.to_bytes(hexstr=commitment_id_hex),
            Web3.to_bytes(hexstr=above18_hex),
            Web3.to_bytes(hexstr=indian_hex),
            Web3.to_bytes(hexstr=gender_hex),
            Web3.to_bytes(hexstr=name_hash_hex),
            Web3.to_bytes(hexstr=validity_hex)
        ).build_transaction({
            "from": account,
            "nonce": nonce,
            "gas": 1_500_000,
            "gasPrice": self.w3.to_wei("2", "gwei")
        })
        signed = self.w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        return receipt.transactionHash.hex()

    def verify_attr(self, method_name: str, commitment_id_hex: str, provided_hex: str) -> bool:
        fn = getattr(self.contract.functions, method_name)
        result = fn(Web3.to_bytes(hexstr=commitment_id_hex),
                    Web3.to_bytes(hexstr=provided_hex)).call()
        return bool(result)
