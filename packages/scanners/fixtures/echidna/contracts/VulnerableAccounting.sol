// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.36;

contract VulnerableAccounting {
    uint256 public recorded;
    uint256 public guard;
    uint256 public mirror;

    function credit(uint256 amount) external {
        recorded += amount;
        guard += amount;
        mirror += amount;
    }

    function debit(uint256 amount) external {
        if (amount > recorded) return;
        recorded -= amount;
        guard -= amount;
        // mirror is intentionally not debited.
    }
}
