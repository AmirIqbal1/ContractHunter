// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { CounterMath } from "./lib/CounterMath.sol";

contract Counter {
    uint256 public count;

    function increment() external {
        count = CounterMath.addOne(count);
    }
}
