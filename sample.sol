// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleRandom {
    uint public lastRandomValue;

    function generateRandom() public returns (uint) {
        uint random = uint(keccak256(abi.encodePacked(block.timestamp, block.difficulty, msg.sender)));
        lastRandomValue = random;
        return random;
    }
}