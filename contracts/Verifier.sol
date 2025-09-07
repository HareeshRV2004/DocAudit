// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Verifier {
    struct AadhaarSet {
        // Commitments are stored as bytes32 (keccak256 hashes)
        bytes32 above18;           // hash(userId || "Above18")
        bytes32 indian;            // hash(userId || "Indian")
        bytes32 gender;            // hash(userId || "Gender:" || M/F)
        bytes32 nameHash;          // hash(userId || "Name:" || nameLowercase)
        bytes32 validity;          // hash(userId || "Valid") == committed if document not tampered
        bool set;
    }

    // commitmentId => AadhaarSet
    mapping(bytes32 => AadhaarSet) private records;

    event AadhaarCommitted(bytes32 indexed commitmentId, address indexed uploader);

    function setAadhaarCommitments(
        bytes32 commitmentId,
        bytes32 above18,
        bytes32 indian,
        bytes32 gender,
        bytes32 nameHash,
        bytes32 validity
    ) external {
        require(!records[commitmentId].set, "Already set");
        records[commitmentId] = AadhaarSet({
            above18: above18,
            indian: indian,
            gender: gender,
            nameHash: nameHash,
            validity: validity,
            set: true
        });
        emit AadhaarCommitted(commitmentId, msg.sender);
    }

    function isSet(bytes32 commitmentId) external view returns (bool) {
        return records[commitmentId].set;
    }

    function verifyAbove18(bytes32 commitmentId, bytes32 provided) external view returns (bool) {
        AadhaarSet storage s = records[commitmentId];
        return s.set && s.above18 == provided;
    }

    function verifyIndian(bytes32 commitmentId, bytes32 provided) external view returns (bool) {
        AadhaarSet storage s = records[commitmentId];
        return s.set && s.indian == provided;
    }

    function verifyGender(bytes32 commitmentId, bytes32 provided) external view returns (bool) {
        AadhaarSet storage s = records[commitmentId];
        return s.set && s.gender == provided;
    }

    function verifyName(bytes32 commitmentId, bytes32 provided) external view returns (bool) {
        AadhaarSet storage s = records[commitmentId];
        return s.set && s.nameHash == provided;
    }

    function verifyValidity(bytes32 commitmentId, bytes32 provided) external view returns (bool) {
        AadhaarSet storage s = records[commitmentId];
        return s.set && s.validity == provided;
    }
}


