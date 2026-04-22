// SPDX-License-Identifier: MIT
pragma solidity 0.8.31;

import {SovraRevocationRegistryV1} from "../revocation-registry/SovraRevocationRegistryV1.sol";

/// @title SovraRevocationRegistryV2Mock - Minimal V2 for upgrade tests
/// @custom:oz-upgrades-from SovraRevocationRegistryV1
contract SovraRevocationRegistryV2Mock is SovraRevocationRegistryV1 {
    function version() external pure returns (uint256) {
        return 2;
    }
}
