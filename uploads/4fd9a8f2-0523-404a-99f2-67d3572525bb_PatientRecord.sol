// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract PatientRecord is Ownable {
    using ECDSA for bytes32;

    struct PatientData {
        string patientId;
        string diagnosisHash;  // e.g., keccak256 of diagnosis
        uint256 timestamp;
        address doctor;
        bytes signature;       // ECDSA signature from doctor
    }

    mapping(string => PatientData[]) public records;

    event RecordAdded(string patientId, address doctor, uint256 timestamp);

    // Doctor signs patient record off-chain and submits
    function addRecord(
        string memory _patientId,
        string memory _diagnosisHash,
        bytes memory _signature
    ) external {
        bytes32 messageHash = keccak256(abi.encodePacked(
            _patientId,
            _diagnosisHash,
            block.timestamp,
            msg.sender
        ));

        address signer = messageHash.recover(_signature);
        require(signer == msg.sender, "Invalid ECDSA signature");

        PatientData memory newRecord = PatientData({
            patientId: _patientId,
            diagnosisHash: _diagnosisHash,
            timestamp: block.timestamp,
            doctor: msg.sender,
            signature: _signature
        });

        records[_patientId].push(newRecord);
        emit RecordAdded(_patientId, msg.sender, block.timestamp);
    }

    // Retrieve records (simplified access control)
    function getRecords(string memory _patientId) external view returns (PatientData[] memory) {
        return records[_patientId];
    }
}