// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Unsafe {
    address public owner;

    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}
