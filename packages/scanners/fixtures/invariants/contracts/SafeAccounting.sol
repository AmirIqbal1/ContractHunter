// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;
contract SafeAccounting {
    uint256 public totalRecordedBalance;
    function record(uint256) external { totalRecordedBalance = address(this).balance; }
}
