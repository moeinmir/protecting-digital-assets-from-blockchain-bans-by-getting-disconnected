// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract Wallet {
    using ECDSA for bytes32;
    address private owner;

    constructor(address _owner) {
        require(_owner != address(0), "Invalid owner address");
        owner = _owner;
    }
    
    receive() external payable {}
    
    fallback() external payable {}
    
    function provideSignatureWithdrawFund(
        address to,
        uint256 amount,
        bytes memory signature,
        address tokenAddress
    ) external {
        require(to != address(0), "Invalid recipient address");
        require(amount > 0, "Amount must be greater than 0");
        bytes32 messageHash = getMessageHash(to, amount, tokenAddress);
        bytes32 ethSignedMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );
        address signer = ECDSA.recover(ethSignedMessageHash, signature);
        require(signer == owner, "Invalid signature");
        
        if (tokenAddress == address(0)) {
            require(address(this).balance >= amount, "Insufficient ETH balance");
            payable(to).transfer(amount);
        } else {
            IERC20 token = IERC20(tokenAddress);
            require(token.balanceOf(address(this)) >= amount, "Insufficient token balance");
            require(token.transfer(to, amount), "Token transfer failed");
        }
    }
    
    function getMessageHash(
        address to,
        uint256 amount,
        address tokenAddress
    ) public view returns (bytes32) {
        return keccak256(abi.encodePacked(
            to,
            amount,
            tokenAddress,
            address(this), 
            block.chainid
        ));
    }
    
    function getOwner() public view returns (address) {
        return owner;
    }
}