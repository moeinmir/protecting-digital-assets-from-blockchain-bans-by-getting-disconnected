
## Breaking the connection to protect our digital assets on public blockchains in front of banning?

### The transaction flow
Despite the decentralized philosophy of public blockchain, in several layers of this economic environment various entities observe transactions. If tracking the IP address lead the observer to some specific region, they may ban the account address and although addresses which did business with it. 
When a transaction is created, it is signed by client secret key, and then is sent to a public RPC provider or a full node, which can be although a miner or not, anyway the transaction will be validated and if pass will be propagated to other peers. Then it will live on these nodes memory pool, till some miner take it, mine it, include it in a block and propagate it. There are analyst nodes in the network who try to find and take action in front of transactions initiated from some specific region, the public RPC provider may try to track the transaction and although every node may take action.

### Common practices
To mitigate the risk of banning, there are some approaches which is recommended and following them depends on our already implemented infrastructure and how fundamental are we ready to refactor. After signing the transaction, instead of sending to one RPC provider or a full node, we can acquire several cloud servers and make them responsible for sending to nodes, we may want to change these servers periodically, and have several full nodes of our own, following the same pattern. I thought that maybe we should categorize transactions and put the ones which have to be executed sequentially in one part. 

Crypto companies do not treat all their assets the same, they store values in several layers in various methods and they may use Hard Secure Devices to manage part of their assets but is not the risk of getting banned always there if we rely completely on the network?

### Making a well distributed combinations of digital assets which we have control on them while those are disconnected from us
Suppose estimated value of our clients assets in our custody is 10 million but we need only 2 million of it to handle our daily requests and the rest rest in rarely touched. Suppose to mitigate the risk we want to put the 7 million of the remaining, some where safe, but we although want to keep the ratio steady meaning if our market cap increased to 20 million we want our support to worth 14 and if decreased to 5 the support value decrease to 3.5. Suppose we do proper risk calculations and the mentioned percentages are pretty accurate and the even if we loose access to all 2 or 3 million at which was at risk, the growth we had can cover the loss, and we are insuring our customer by our own calculation and there is no surprise if we lose all 2 or 3 million. Now how can we achieve this? 
My idea is relatively simple whether it is practical or not.
Let's put it in simple terms.

!["zones and players"](./asset/diagram/interaction-between-wallets-factory-internediary-and-players-overseas.png)

#### Assumptions
- Tracking is done based on IP addresses and if a smart contract is deployed from a clean region, and ones communicating with it are from clean region, there is no risk of being reported.
- We do not consider the possibility of malicious actions to disrupt some smart contract reputation.

#### Smart contracts
##### Wallet 
- these smart contracts can be funded with cypto or tokens but only the one who present our specific message with our signature can withdraw based on the message we signed

##### Factory
- this smart contract will be responsible for creating and deploying wallets

#### Players
##### Individual overseas willing to accept or give up none digital assets like fiat money or gold and charge or withdraw (with our provided singed message) from wallet
##### Our direct colleague who communicate with calculating module and then with individuals overseas to keep the ratio as it should be

#### Capital evaluation and ratio calculation module
- this module will use the data provided in our core services and although data about prices and prepare reports about proper ratio

#### The flow
- Our colleague will communicate with our calculating module to see what combination is proper now, then it will communicate with players overseas and ask them to create wallet using factory and fund, or provide them signed messages so they could withdraw from them. We suppose the process of transferring none digital assets can be managed. 


#### When is this reasonable
what we discussed required to transfer a big proportion of our capital overseas, in a restricted environment, it does not seem reasonable. maybe it is true but note that we only do this once, and then the value we are transferring is limited.



#### Wallet contract code
```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureWallet {
    using ECDSA for bytes32;
    
    // Public key that controls this wallet (address derived from it)
    address public owner;
    
    // Events
    event ETHTransferred(address indexed to, uint256 amount);
    event TokenTransferred(address indexed token, address indexed to, uint256 amount);
    event OwnershipTransferred(address indexed newOwner);
    
    // Modifier to check if the caller is the owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }
    
    // Constructor sets the initial owner
    constructor(address _owner) {
        require(_owner != address(0), "Invalid owner address");
        owner = _owner;
    }
    
    // Receive function to accept ETH
    receive() external payable {}
    
    // Fallback function to accept ETH
    fallback() external payable {}
    
    /**
     * @dev Transfer ETH using signature verification
     * @param to Recipient address
     * @param amount Amount of ETH to transfer
     * @param signature ECDSA signature of the message
     * @param tokenAddress Address(0) for ETH transfers
     */
    function transferWithSignature(
        address to,
        uint256 amount,
        bytes memory signature,
        address tokenAddress
    ) external {
        require(to != address(0), "Invalid recipient address");
        require(amount > 0, "Amount must be greater than 0");
        
        // Create the message hash that should have been signed
        bytes32 messageHash = getMessageHash(to, amount, tokenAddress);
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        
        // Recover the signer from the signature
        address recoveredSigner = ethSignedMessageHash.recover(signature);
        
        // Verify the recovered signer is the owner
        require(recoveredSigner == owner, "Invalid signature");
        
        if (tokenAddress == address(0)) {
            // ETH transfer
            require(address(this).balance >= amount, "Insufficient ETH balance");
            payable(to).transfer(amount);
            emit ETHTransferred(to, amount);
        } else {
            // ERC20 token transfer
            IERC20 token = IERC20(tokenAddress);
            require(token.balanceOf(address(this)) >= amount, "Insufficient token balance");
            require(token.transfer(to, amount), "Token transfer failed");
            emit TokenTransferred(tokenAddress, to, amount);
        }
    }
    
    /**
     * @dev Get the message hash that should be signed
     * @param to Recipient address
     * @param amount Amount to transfer
     * @param tokenAddress Token address (address(0) for ETH)
     */
    function getMessageHash(
        address to,
        uint256 amount,
        address tokenAddress
    ) public view returns (bytes32) {
        return keccak256(abi.encodePacked(
            to,
            amount,
            tokenAddress,
            address(this), // Include contract address to prevent replay attacks
            block.chainid // Include chain ID to prevent cross-chain replay attacks
        ));
    }
    
    /**
     * @dev Transfer ownership to a new public key
     * @param newOwner New owner address
     * @param signature Signature from current owner approving the transfer
     */
    function transferOwnership(
        address newOwner,
        bytes memory signature
    ) external {
        require(newOwner != address(0), "Invalid new owner address");
        
        // Create the message hash for ownership transfer
        bytes32 messageHash = keccak256(abi.encodePacked(
            newOwner,
            address(this),
            block.chainid,
            "transferOwnership"
        ));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        
        // Recover the signer
        address recoveredSigner = ethSignedMessageHash.recover(signature);
        
        // Verify the recovered signer is the current owner
        require(recoveredSigner == owner, "Invalid signature for ownership transfer");
        
        // Transfer ownership
        address oldOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(newOwner);
    }
    
    /**
     * @dev Get ETH balance of the contract
     */
    function getETHBalance() external view returns (uint256) {
        return address(this).balance;
    }
    
    /**
     * @dev Get ERC20 token balance of the contract
     * @param tokenAddress Address of the ERC20 token
     */
    function getTokenBalance(address tokenAddress) external view returns (uint256) {
        return IERC20(tokenAddress).balanceOf(address(this));
    }
    
    /**
     * @dev Emergency function to transfer ownership (only callable by current owner)
     * This provides a fallback if the private key is lost but the owner still has access
     */
    function emergencyTransferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid new owner address");
        owner = newOwner;
        emit OwnershipTransferred(newOwner);
    }
}
```



#### WalletFactory contract code
```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

// Import the SecureWallet contract (assuming it's in the same project)
import "./SecureWallet.sol";

contract WalletFactory {
    using ECDSA for bytes32;
    
    // Address that can authorize wallet creation
    address public signer;
    
    // Mapping to track deployed wallets for each owner
    mapping(address => address) public ownerToWallet;
    
    // Mapping to check if a wallet address was deployed by this factory
    mapping(address => bool) public isWalletDeployedByFactory;
    
    // Counter for nonce to prevent replay attacks
    mapping(address => uint256) public nonces;
    
    // Events
    event WalletCreated(address indexed owner, address indexed walletAddress);
    event SignerChanged(address indexed newSigner);
    
    // Modifier to check if caller is the current signer
    modifier onlySigner() {
        require(msg.sender == signer, "Only signer can call this function");
        _;
    }
    
    /**
     * @dev Constructor sets the initial signer
     * @param _signer Address that will sign wallet creation requests
     */
    constructor(address _signer) {
        require(_signer != address(0), "Invalid signer address");
        signer = _signer;
    }
    
    /**
     * @dev Create a new wallet for the specified owner using signature verification
     * @param owner Address that will own the new wallet
     * @param signature ECDSA signature authorizing wallet creation
     */
    function createWallet(
        address owner,
        bytes memory signature
    ) external returns (address walletAddress) {
        require(owner != address(0), "Invalid owner address");
        require(ownerToWallet[owner] == address(0), "Wallet already exists for this owner");
        
        // Create the message hash that should have been signed
        bytes32 messageHash = getCreateWalletMessageHash(owner);
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        
        // Recover the signer from the signature
        address recoveredSigner = ethSignedMessageHash.recover(signature);
        
        // Verify the recovered signer is the authorized signer
        require(recoveredSigner == signer, "Invalid signature for wallet creation");
        
        // Deploy the new wallet
        walletAddress = address(new SecureWallet(owner));
        
        // Update mappings
        ownerToWallet[owner] = walletAddress;
        isWalletDeployedByFactory[walletAddress] = true;
        nonces[owner]++;
        
        emit WalletCreated(owner, walletAddress);
        
        return walletAddress;
    }
    
    /**
     * @dev Create a new wallet with salt for deterministic address
     * @param owner Address that will own the new wallet
     * @param signature ECDSA signature authorizing wallet creation
     * @param salt Salt for deterministic deployment
     */
    function createWalletDeterministic(
        address owner,
        bytes memory signature,
        bytes32 salt
    ) external returns (address walletAddress) {
        require(owner != address(0), "Invalid owner address");
        require(ownerToWallet[owner] == address(0), "Wallet already exists for this owner");
        
        // Create the message hash that should have been signed (include salt for uniqueness)
        bytes32 messageHash = getCreateWalletMessageHashWithSalt(owner, salt);
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        
        // Recover the signer from the signature
        address recoveredSigner = ethSignedMessageHash.recover(signature);
        
        // Verify the recovered signer is the authorized signer
        require(recoveredSigner == signer, "Invalid signature for wallet creation");
        
        // Deploy the new wallet with CREATE2 for deterministic address
        walletAddress = address(new SecureWallet{salt: salt}(owner));
        
        // Update mappings
        ownerToWallet[owner] = walletAddress;
        isWalletDeployedByFactory[walletAddress] = true;
        nonces[owner]++;
        
        emit WalletCreated(owner, walletAddress);
        
        return walletAddress;
    }
    
    /**
     * @dev Batch create multiple wallets
     * @param owners Array of owner addresses
     * @param signatures Array of signatures for each owner
     */
    function createWalletsBatch(
        address[] memory owners,
        bytes[] memory signatures
    ) external returns (address[] memory) {
        require(owners.length == signatures.length, "Arrays length mismatch");
        require(owners.length > 0, "Empty arrays");
        require(owners.length <= 50, "Too many wallets in batch"); // Prevent gas limits
        
        address[] memory deployedWallets = new address[](owners.length);
        
        for (uint256 i = 0; i < owners.length; i++) {
            address owner = owners[i];
            require(owner != address(0), "Invalid owner address");
            require(ownerToWallet[owner] == address(0), "Wallet already exists for this owner");
            
            // Create the message hash that should have been signed
            bytes32 messageHash = getCreateWalletMessageHash(owner);
            bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
            
            // Recover the signer from the signature
            address recoveredSigner = ethSignedMessageHash.recover(signatures[i]);
            
            // Verify the recovered signer is the authorized signer
            require(recoveredSigner == signer, "Invalid signature for wallet creation");
            
            // Deploy the new wallet
            address walletAddress = address(new SecureWallet(owner));
            
            // Update mappings
            ownerToWallet[owner] = walletAddress;
            isWalletDeployedByFactory[walletAddress] = true;
            nonces[owner]++;
            
            deployedWallets[i] = walletAddress;
            emit WalletCreated(owner, walletAddress);
        }
        
        return deployedWallets;
    }
    
    /**
     * @dev Get the message hash that should be signed for wallet creation
     * @param owner The owner address for the new wallet
     */
    function getCreateWalletMessageHash(
        address owner
    ) public view returns (bytes32) {
        return keccak256(abi.encodePacked(
            owner,
            address(this),
            block.chainid,
            nonces[owner],
            "createWallet"
        ));
    }
    
    /**
     * @dev Get the message hash that should be signed for deterministic wallet creation
     * @param owner The owner address for the new wallet
     * @param salt The salt for deterministic deployment
     */
    function getCreateWalletMessageHashWithSalt(
        address owner,
        bytes32 salt
    ) public view returns (bytes32) {
        return keccak256(abi.encodePacked(
            owner,
            salt,
            address(this),
            block.chainid,
            nonces[owner],
            "createWalletDeterministic"
        ));
    }
    
    /**
     * @dev Predict the address of a wallet that would be deployed deterministically
     * @param owner The owner address for the wallet
     * @param salt The salt for deterministic deployment
     */
    function predictWalletAddress(
        address owner,
        bytes32 salt
    ) public view returns (address) {
        bytes memory bytecode = type(SecureWallet).creationCode;
        bytes memory constructorArgs = abi.encode(owner);
        bytes memory creationCode = abi.encodePacked(bytecode, constructorArgs);
        
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(creationCode)
            )
        );
        
        return address(uint160(uint256(hash)));
    }
    
    /**
     * @dev Get wallet address for an owner
     * @param owner The owner address
     */
    function getWalletForOwner(address owner) external view returns (address) {
        return ownerToWallet[owner];
    }
    
    /**
     * @dev Check if a wallet was deployed by this factory
     * @param walletAddress The wallet address to check
     */
    function isDeployedByFactory(address walletAddress) external view returns (bool) {
        return isWalletDeployedByFactory[walletAddress];
    }
    
    /**
     * @dev Change the signer address (only callable by current signer)
     * @param newSigner The new signer address
     */
    function changeSigner(address newSigner) external onlySigner {
        require(newSigner != address(0), "Invalid signer address");
        signer = newSigner;
        emit SignerChanged(newSigner);
    }
    
    /**
     * @dev Get the current nonce for an owner
     * @param owner The owner address
     */
    function getNonce(address owner) external view returns (uint256) {
        return nonces[owner];
    }
}
```
#### WalletSignatureHelper contract code
```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SignatureHelper {
    using ECDSA for bytes32;
    
    /**
     * @dev Generate the message hash that should be signed for a transfer
     */
    function getTransferMessageHash(
        address to,
        uint256 amount,
        address tokenAddress,
        address walletAddress,
        uint256 chainId
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            to,
            amount,
            tokenAddress,
            walletAddress,
            chainId
        ));
    }
    
    /**
     * @dev Generate the message hash that should be signed for ownership transfer
     */
    function getOwnershipTransferMessageHash(
        address newOwner,
        address walletAddress,
        uint256 chainId
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            newOwner,
            walletAddress,
            chainId,
            "transferOwnership"
        ));
    }
    
    /**
     * @dev Get the ETH signed message hash (what actually gets signed)
     */
    function getEthSignedMessageHash(bytes32 messageHash) public pure returns (bytes32) {
        return messageHash.toEthSignedMessageHash();
    }
}
```

#### WalletFactorySignatureHelper contract code

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract WalletFactorySignatureHelper {
    using ECDSA for bytes32;
    
    /**
     * @dev Generate the message hash for wallet creation
     */
    function getCreateWalletMessageHash(
        address owner,
        address factoryAddress,
        uint256 chainId,
        uint256 nonce
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            owner,
            factoryAddress,
            chainId,
            nonce,
            "createWallet"
        ));
    }
    
    /**
     * @dev Generate the message hash for deterministic wallet creation
     */
    function getCreateWalletMessageHashWithSalt(
        address owner,
        bytes32 salt,
        address factoryAddress,
        uint256 chainId,
        uint256 nonce
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            owner,
            salt,
            factoryAddress,
            chainId,
            nonce,
            "createWalletDeterministic"
        ));
    }
    
    /**
     * @dev Get the ETH signed message hash (what actually gets signed)
     */
    function getEthSignedMessageHash(bytes32 messageHash) public pure returns (bytes32) {
        return messageHash.toEthSignedMessageHash();
    }
    
    /**
     * @dev Verify a signature for wallet creation
     */
    function verifyCreateWalletSignature(
        address owner,
        address factoryAddress,
        uint256 chainId,
        uint256 nonce,
        bytes memory signature,
        address expectedSigner
    ) public pure returns (bool) {
        bytes32 messageHash = getCreateWalletMessageHash(owner, factoryAddress, chainId, nonce);
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        address recoveredSigner = ethSignedMessageHash.recover(signature);
        
        return recoveredSigner == expectedSigner;
    }
}
```


