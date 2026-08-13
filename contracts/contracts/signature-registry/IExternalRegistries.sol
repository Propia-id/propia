// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

interface IKeyRegistry {
    struct VerificationMethod {
        bytes32 id;
        uint8 keyType;
        bytes32 pubKeyX;
        bytes32 pubKeyY;
        uint8 relationships;
    }

    struct ServiceEndpoint {
        bytes32 id;
        bytes32 serviceType;
        string endpoint;
    }

    function resolve(address identity)
        external
        view
        returns (
            VerificationMethod[] memory methods,
            ServiceEndpoint[] memory services,
            uint64 created,
            uint64 updated,
            uint32 versionId,
            bool deactivated
        );
}

interface IAuthorizationRegistry {
    function isTrusted(address account, bytes32 typeId) external view returns (bool);
}
