// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

import {SovraIssuerRegistryV1} from "../issuer-registry/SovraIssuerRegistryV1.sol";

/// @title SovraIssuerRegistryV2Mock - Minimal V2 for upgrade tests
/// @custom:oz-upgrades-from SovraIssuerRegistryV1
contract SovraIssuerRegistryV2Mock is SovraIssuerRegistryV1 {
    function version() external pure returns (uint256) {
        return 2;
    }
}
