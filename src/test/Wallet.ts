import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { network } from "hardhat";
import { parseEther } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

describe("WalletFactory + Wallet", async function () {
    const { viem } = await network.connect();
    const publicClient = await viem.getPublicClient();
    const [deployer, user, recipient] = await viem.getWalletClients();

    it("Should deploy WalletFactory and create signed message for wallet creation", async function () {
        const signerPrivateKey = generatePrivateKey();
        const signerAccount = privateKeyToAccount(signerPrivateKey);
        const walletFactory = await viem.deployContract("WalletFactory", [signerAccount.address]);

        const walletOwner = deployer.account.address;
        const salt = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

        const messageHash = await walletFactory.read.getCreateWalletMessageHashWithSalt([walletOwner, salt]);
        const signature = await signerAccount.signMessage({ message: { raw: messageHash } });

        assert.ok(walletFactory.address, "WalletFactory should be deployed");
        assert.ok(messageHash, "Message hash should be generated");
        assert.ok(signature, "Signature should be generated");
    });

    it("Should create wallet with correct signature", async function () {
        const signerPrivateKey = generatePrivateKey();
        const signerAccount = privateKeyToAccount(signerPrivateKey);
        const walletFactory = await viem.deployContract("WalletFactory", [signerAccount.address]);
        const walletOwner = user.account.address;
        const salt = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        const messageHash = await walletFactory.read.getCreateWalletMessageHashWithSalt([walletOwner, salt]);
        const correctSignature = await signerAccount.signMessage({ message: { raw: messageHash } });
        const txHash = await walletFactory.write.createWallet([walletOwner, correctSignature, salt]);
        const receipt = await publicClient.getTransactionReceipt({ hash: txHash });
        assert.equal(receipt.status, "success", "Transaction should succeed with correct signature");
    });

    it("Should fail to create wallet with wrong signature", async function () {
        const signerPrivateKey = generatePrivateKey();
        const signerAccount = privateKeyToAccount(signerPrivateKey);
        const wrongSignerPrivateKey = generatePrivateKey();
        const wrongSignerAccount = privateKeyToAccount(wrongSignerPrivateKey);
        const walletFactory = await viem.deployContract("WalletFactory", [signerAccount.address]);
        const walletOwner = user.account.address;
        const salt = "0x2234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        const messageHash = await walletFactory.read.getCreateWalletMessageHashWithSalt([walletOwner, salt]);
        const wrongSignature = await wrongSignerAccount.signMessage({ message: { raw: messageHash } });
        try {
            await walletFactory.write.createWallet([walletOwner, wrongSignature, salt]);
            assert.fail("Transaction should have failed with wrong signature");
        } catch (error: any) {
            assert.ok(
                error.message.includes("Invalid signature for wallet creation") ||
                error.message.includes("revert"),
                `Expected signature validation error, but got: ${error.message}`
            );
        }
    });

    it("Should transfer ETH with correct signature", async function () {
        const signerPrivateKey = generatePrivateKey();
        const signerAccount = privateKeyToAccount(signerPrivateKey);
        const walletFactory = await viem.deployContract("WalletFactory", [signerAccount.address]);
        const walletOwner = signerAccount.address;
        const salt = "0x3234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        const messageHash = await walletFactory.read.getCreateWalletMessageHashWithSalt([walletOwner, salt]);
        const correctSignature = await signerAccount.signMessage({ message: { raw: messageHash } });
        const simulation = await publicClient.simulateContract({
            address: walletFactory.address,
            abi: walletFactory.abi,
            functionName: 'createWallet',
            args: [walletOwner, correctSignature, salt],
            account: deployer.account.address
        });
        const walletAddress = simulation.result;
        const txHash = await walletFactory.write.createWallet([walletOwner, correctSignature, salt]);
        const receipt = await publicClient.getTransactionReceipt({ hash: txHash });
        const walletContract = await viem.getContractAt("Wallet", walletAddress);
        const actualOwner = await walletContract.read.getOwner();
        assert.equal(actualOwner, walletOwner, "Wallet should have correct owner");
        await deployer.sendTransaction({
            to: walletAddress,
            value: parseEther("1")
        });
        const walletBalance = await publicClient.getBalance({ address: walletAddress });
        assert.equal(walletBalance, parseEther("1"), "Wallet should have 1 ETH");
        const transferAmount = parseEther("0.5");
        const transferMessageHash = await walletContract.read.getMessageHash([
            recipient.account.address,
            transferAmount,
            "0x0000000000000000000000000000000000000000"
        ]);
        const transferSignature = await signerAccount.signMessage({
            message: { raw: transferMessageHash }
        });
        const transferTx = await walletContract.write.provideSignatureWithdrawFund([
            recipient.account.address,
            transferAmount,
            transferSignature,
            "0x0000000000000000000000000000000000000000"
        ]);

        const transferReceipt = await publicClient.getTransactionReceipt({ hash: transferTx });
        assert.equal(transferReceipt.status, "success", "ETH transfer should succeed with correct signature");
        const recipientBalance = await publicClient.getBalance({ address: recipient.account.address });
    });

    it("Should fail ETH transfer with incorrect signature", async function () {
        const signerPrivateKey = generatePrivateKey();
        const signerAccount = privateKeyToAccount(signerPrivateKey);
        const wrongSignerPrivateKey = generatePrivateKey();
        const wrongSignerAccount = privateKeyToAccount(wrongSignerPrivateKey);
        const walletFactory = await viem.deployContract("WalletFactory", [signerAccount.address]);
        const walletOwner = signerAccount.address;
        const salt = "0x4234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        const messageHash = await walletFactory.read.getCreateWalletMessageHashWithSalt([walletOwner, salt]);
        const correctSignature = await signerAccount.signMessage({ message: { raw: messageHash } });
        const simulation = await publicClient.simulateContract({
            address: walletFactory.address,
            abi: walletFactory.abi,
            functionName: 'createWallet',
            args: [walletOwner, correctSignature, salt],
            account: deployer.account.address
        });
        const walletAddress = simulation.result;
        await walletFactory.write.createWallet([walletOwner, correctSignature, salt]);
        await deployer.sendTransaction({
            to: walletAddress,
            value: parseEther("1")
        });
        const transferAmount = parseEther("0.5");
        const walletContract = await viem.getContractAt("Wallet", walletAddress);
        const transferMessageHash = await walletContract.read.getMessageHash([
            recipient.account.address,
            transferAmount,
            "0x0000000000000000000000000000000000000000"
        ]);
        const wrongTransferSignature = await wrongSignerAccount.signMessage({
            message: { raw: transferMessageHash }
        });
        try {
            await walletContract.write.provideSignatureWithdrawFund([
                recipient.account.address,
                transferAmount,
                wrongTransferSignature,
                "0x0000000000000000000000000000000000000000"
            ]);
            assert.fail("ETH transfer should have failed with wrong signature");
        } catch (error: any) {
            assert.ok(
                error.message.includes("Invalid signature") ||
                error.message.includes("revert"),
                `Expected signature validation error, but got: ${error.message}`
            );
        }
    });
});