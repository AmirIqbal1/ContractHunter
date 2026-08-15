// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Unit } from "./Unit.sol";

library CounterMath {
    function addOne(uint256 value) internal pure returns (uint256) {
        return value + Unit.value();
    }
}
