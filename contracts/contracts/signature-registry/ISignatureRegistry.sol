// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

interface ISignatureRegistry {
    struct Record {
        bytes32 r;
        bytes32 s;
        uint64 recordedAt;
    }

    error AlreadyRecorded();

    error NotAuthorized();

    error NoRegisteredKey();

    error InvalidSignature();

    error EmptyDigest();

    event SignatureRecorded(address indexed signer, bytes32 indexed digest, uint64 recordedAt);

    function record(address signer, bytes32 typeId, bytes32 digest, bytes32 r, bytes32 s) external;

    function getRecord(address signer, bytes32 digest) external view returns (Record memory);

    function isRecorded(address signer, bytes32 digest) external view returns (bool);
}
