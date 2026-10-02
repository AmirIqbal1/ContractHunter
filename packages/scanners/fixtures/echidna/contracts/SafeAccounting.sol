// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.36;

contract SafeAccounting {
    uint256 public recorded;
    uint256 public mirror;

    function credit(uint256 amount) external {
        recorded += amount;
        mirror += amount;
    }

    function debit(uint256 amount) external {
        if (amount > recorded) return;
        recorded -= amount;
        mirror -= amount;
    }
}
