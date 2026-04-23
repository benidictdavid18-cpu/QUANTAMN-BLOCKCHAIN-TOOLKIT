from web3 import Web3
import json
import os
from typing import Tuple

class BlockchainStorage:
    def __init__(self):
        # ✅ Sepolia RPC
        self.rpc_url = "https://sepolia.gateway.tenderly.co"
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))

        # ✅ YOUR PRIVATE KEY
        self.private_key = "0xcd77041fae444e1b96881daa0f8736345beefe76caa7ad52abcbf7c4098ff52b"

        self.account = self.w3.eth.account.from_key(self.private_key)

        # ✅ CONTRACT
        self.contract_address = Web3.to_checksum_address("0x9F7946197AD3693e79948a229AAf177fAC3644Bf")

        self.contract_abi = [
            {
                "inputs": [
                    {"internalType": "string", "name": "scanId", "type": "string"},
                    {"internalType": "string", "name": "company", "type": "string"},
                    {"internalType": "uint256", "name": "riskScore", "type": "uint256"},
                    {"internalType": "bytes32", "name": "dataHash", "type": "bytes32"}
                ],
                "name": "storeProof",
                "outputs": [],
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ]

        self.contract = self.w3.eth.contract(
            address=self.contract_address,
            abi=self.contract_abi
        )

    def store_migration_proof(
        self,
        scan_id: str,
        company_name: str,
        timestamp: str,
        vulnerabilities_count: int,
        risk_score: float
    ) -> Tuple[str, int]:

        try:
            # ✅ Create hash
            proof_data = {
                "scan_id": scan_id,
                "company_name": company_name,
                "timestamp": timestamp,
                "vulnerabilities_count": vulnerabilities_count,
                "risk_score": risk_score
            }

            proof_json = json.dumps(proof_data, sort_keys=True)
            data_hash = self.w3.keccak(text=proof_json)

            nonce = self.w3.eth.get_transaction_count(self.account.address)

            # ✅ TX
            tx = self.contract.functions.storeProof(
                scan_id,
                company_name,
                int(risk_score),
                data_hash
            ).build_transaction({
                'from': self.account.address,
                'nonce': nonce,
                'gas': 300000,
                'maxFeePerGas': self.w3.to_wei('20', 'gwei'),
                'maxPriorityFeePerGas': self.w3.to_wei('2', 'gwei'),
                'chainId': 11155111
            })

            signed_tx = self.w3.eth.account.sign_transaction(tx, self.private_key)

            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)

            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            # ✅ FINAL FIX (IMPORTANT)
            return self.w3.to_hex(tx_hash), receipt.blockNumber

        except Exception as e:
            print("BLOCKCHAIN ERROR:", str(e))
            raise