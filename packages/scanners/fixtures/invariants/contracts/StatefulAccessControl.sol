// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.24;
contract StatefulAccessControl {
    address public owner;
    constructor() { owner = msg.sender; }
    function transferOwnership(address nextOwner) external { owner = nextOwner; }
    function touch(bool) external { }
}
