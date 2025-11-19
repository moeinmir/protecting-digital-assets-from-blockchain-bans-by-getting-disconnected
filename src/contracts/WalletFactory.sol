// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./Wallet.sol";

contract WalletFactory {
    address private signer;

    constructor(address _signer) {
        require(_signer != address(0), "Invalid signer address");
        signer = _signer;
    }
    
    function createWallet(
        address owner,
        bytes memory signature,
        bytes32 salt
    ) external returns (address walletAddress) {
        require(owner != address(0), "Invalid owner address");
        bytes32 messageHash = getCreateWalletMessageHashWithSalt(owner, salt);
        bytes32 ethSignedMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );
        address recoveredSigner = ECDSA.recover(ethSignedMessageHash, signature);
        require(recoveredSigner == signer, "Invalid signature for wallet creation");
        walletAddress = address(new Wallet{salt: salt}(owner));
        return walletAddress;
    }
    
    function getCreateWalletMessageHashWithSalt(
        address owner,
        bytes32 salt
    ) public view returns (bytes32) {
        return keccak256(abi.encodePacked(
            owner,
            salt,
            address(this),
            block.chainid
        ));
    }
    
    function getSigner() public view returns (address) {
        return signer;
    }
}