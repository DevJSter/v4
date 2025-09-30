# Uniswap v4 Hook Template

**A template for writing Uniswap v4 Hooks 🦄**

### Get Started

This template provides a starting point for writing Uniswap v4 Hooks, including a simple example and preconfigured test environment. Start by creating a new repository using the "Use this template" button at the top right of this page. Alternatively you can also click this link:

[![Use this Template](https://img.shields.io/badge/Use%20this%20Template-101010?style=for-the-badge&logo=github)](https://github.com/uniswapfoundation/v4-template/generate)

1. The example hook [Counter.sol](src/Counter.sol) demonstrates the `beforeSwap()` and `afterSwap()` hooks
2. The test template [Counter.t.sol](test/Counter.t.sol) preconfigures the v4 pool manager, test tokens, and test liquidity.

<details>
<summary>Updating to v4-template:latest</summary>

This template is actively maintained -- you can update the v4 dependencies, scripts, and helpers:

```bash
git remote add template https://github.com/uniswapfoundation/v4-template
git fetch template
git merge template/main <BRANCH> --allow-unrelated-histories
```

</details>

### Requirements

This template is designed to work with Foundry (stable). If you are using Foundry Nightly, you may encounter compatibility issues. You can update your Foundry installation to the latest stable version by running:

```
foundryup
```

To set up the project, run the following commands in your terminal to install dependencies and run the tests:

```
forge install
forge test
```

### Local Development

Other than writing unit tests (recommended!), you can only deploy & test hooks on [anvil](https://book.getfoundry.sh/anvil/) locally. Scripts are available in the `script/` directory, which can be used to deploy hooks, create pools, provide liquidity and swap tokens. The scripts support both local `anvil` environment as well as running them directly on a production network.

### Executing locally with using **Anvil**:

1. Start Anvil (or fork a specific chain using anvil):

```bash
anvil
```

or

```bash
anvil --fork-url <YOUR_RPC_URL>
```

2. Execute scripts:

```bash
forge script script/00_DeployHook.s.sol \
    --rpc-url http://localhost:8545 \
    --private-key 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d \
    --broadcast
```

### Using **RPC URLs** (actual transactions):

:::info
It is best to not store your private key even in .env or enter it directly in the command line. Instead use the `--account` flag to select your private key from your keystore.
:::

### Follow these steps if you have not stored your private key in the keystore:

<details>

1. Add your private key to the keystore:

```bash
cast wallet import <SET_A_NAME_FOR_KEY> --interactive
```

2. You will prompted to enter your private key and set a password, fill and press enter:

```
Enter private key: <YOUR_PRIVATE_KEY>
Enter keystore password: <SET_NEW_PASSWORD>
```

You should see this:

```
`<YOUR_WALLET_PRIVATE_KEY_NAME>` keystore was saved successfully. Address: <YOUR_WALLET_ADDRESS>
```

::: warning
Use ```history -c``` to clear your command history.
:::

</details>

1. Execute scripts:

```bash
forge script script/00_DeployHook.s.sol \
    --rpc-url <YOUR_RPC_URL> \
    --account <YOUR_WALLET_PRIVATE_KEY_NAME> \
    --sender <YOUR_WALLET_ADDRESS> \
    --broadcast
```

You will prompted to enter your wallet password, fill and press enter:

```
Enter keystore password: <YOUR_PASSWORD>
```

### Key Modifications to note:

1. Update the `token0` and `token1` addresses in the `BaseScript.sol` file to match the tokens you want to use in the network of your choice for sepolia and mainnet deployments.
2. Update the `token0Amount` and `token1Amount` in the `CreatePoolAndAddLiquidity.s.sol` file to match the amount of tokens you want to provide liquidity with.
3. Update the `token0Amount` and `token1Amount` in the `AddLiquidity.s.sol` file to match the amount of tokens you want to provide liquidity with.
4. Update the `amountIn` and `amountOutMin` in the `Swap.s.sol` file to match the amount of tokens you want to swap.


### Troubleshooting

<details>

#### Permission Denied

When installing dependencies with `forge install`, Github may throw a `Permission Denied` error

Typically caused by missing Github SSH keys, and can be resolved by following the steps [here](https://docs.github.com/en/github/authenticating-to-github/connecting-to-github-with-ssh)

Or [adding the keys to your ssh-agent](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent#adding-your-ssh-key-to-the-ssh-agent), if you have already uploaded SSH keys

#### Anvil fork test failures

Some versions of Foundry may limit contract code size to ~25kb, which could prevent local tests to fail. You can resolve this by setting the `code-size-limit` flag

```
anvil --code-size-limit 40000
```

#### Hook deployment failures

Hook deployment failures are caused by incorrect flags or incorrect salt mining

1. Verify the flags are in agreement:
   - `getHookCalls()` returns the correct flags
   - `flags` provided to `HookMiner.find(...)`
2. Verify salt mining is correct:
   - In **forge test**: the _deployer_ for: `new Hook{salt: salt}(...)` and `HookMiner.find(deployer, ...)` are the same. This will be `address(this)`. If using `vm.prank`, the deployer will be the pranking address
   - In **forge script**: the deployer must be the CREATE2 Proxy: `0x4e59b44847b379578588920cA78FbF26c0B4956C`
     - If anvil does not have the CREATE2 deployer, your foundry may be out of date. You can update it with `foundryup`

</details>

### Additional Resources

- [Uniswap v4 docs](https://docs.uniswap.org/contracts/v4/overview)
- [v4-periphery](https://github.com/uniswap/v4-periphery)
- [v4-core](https://github.com/uniswap/v4-core)
- [v4-by-example](https://v4-by-example.org)


// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract CrossChainEscrow is ReentrancyGuard {
    using SafeERC20 for IERC20;

    struct EscrowData {
        address user;
        address resolver;
        address token;
        uint256 amount;
        uint256 safetyDeposit;
        bytes32 secretCommitment; // Merkle root of secrets
        uint256 deadline;
        uint256 destinationChainId;
        bool executed;
        bool cancelled;
        uint8 totalFillPercentage;
    }

    struct FillData {
        uint8 percentage;
        bytes32 secret;
        bool executed;
    }

    mapping(bytes32 => EscrowData) public escrows;
    mapping(bytes32 => mapping(uint8 => FillData)) public fills;
    mapping(address => bool) public authorizedResolvers;
    
    address public owner;
    uint256 public constant MIN_SAFETY_DEPOSIT_PERCENTAGE = 110; // 110% of swap value
    uint256 public constant MAX_FILL_PERCENTAGE = 100;

    event EscrowCreated(
        bytes32 indexed intentHash,
        address indexed user,
        address indexed resolver,
        address token,
        uint256 amount,
        bytes32 secretCommitment,
        uint256 deadline,
        uint256 destinationChainId
    );

    event FillExecuted(
        bytes32 indexed intentHash,
        uint8 percentage,
        bytes32 secret,
        address executor
    );

    event EscrowCompleted(bytes32 indexed intentHash);
    event EscrowCancelled(bytes32 indexed intentHash);

    modifier onlyAuthorizedResolver() {
        require(authorizedResolvers[msg.sender], "Unauthorized resolver");
        _;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function authorizeResolver(address resolver) external onlyOwner {
        authorizedResolvers[resolver] = true;
    }

    function createEscrow(
        bytes32 intentHash,
        address user,
        address token,
        uint256 amount,
        bytes32 secretCommitment,
        uint256 deadline,
        uint256 destinationChainId
    ) external payable onlyAuthorizedResolver nonReentrant {
        require(escrows[intentHash].user == address(0), "Escrow already exists");
        require(deadline > block.timestamp, "Invalid deadline");
        require(amount > 0, "Invalid amount");
        
        // Calculate required safety deposit
        uint256 requiredSafetyDeposit = calculateSafetyDeposit(amount);
        require(msg.value >= requiredSafetyDeposit, "Insufficient safety deposit");

        // Transfer user tokens to escrow
        IERC20(token).safeTransferFrom(user, address(this), amount);

        escrows[intentHash] = EscrowData({
            user: user,
            resolver: msg.sender,
            token: token,
            amount: amount,
            safetyDeposit: msg.value,
            secretCommitment: secretCommitment,
            deadline: deadline,
            destinationChainId: destinationChainId,
            executed: false,
            cancelled: false,
            totalFillPercentage: 0
        });

        emit EscrowCreated(
            intentHash,
            user,
            msg.sender,
            token,
            amount,
            secretCommitment,
            deadline,
            destinationChainId
        );
    }

    function executeFill(
        bytes32 intentHash,
        uint8 fillPercentage,
        bytes32 secret,
        bytes32[] calldata merkleProof
    ) external nonReentrant {
        EscrowData storage escrow = escrows[intentHash];
        require(escrow.user != address(0), "Escrow does not exist");
        require(!escrow.executed && !escrow.cancelled, "Escrow not active");
        require(block.timestamp <= escrow.deadline, "Escrow expired");
        require(fillPercentage > 0 && fillPercentage <= 25, "Invalid fill percentage");
        require(escrow.totalFillPercentage + fillPercentage <= MAX_FILL_PERCENTAGE, "Exceeds max fill");
        require(!fills[intentHash][fillPercentage].executed, "Fill already executed");

        // Verify secret is in merkle tree
        bytes32 leaf = keccak256(abi.encodePacked(fillPercentage, secret));
        require(
            MerkleProof.verify(merkleProof, escrow.secretCommitment, leaf),
            "Invalid merkle proof"
        );

        // Record fill
        fills[intentHash][fillPercentage] = FillData({
            percentage: fillPercentage,
            secret: secret,
            executed: true
        });

        escrow.totalFillPercentage += fillPercentage;

        // Calculate fill amount
        uint256 fillAmount = (escrow.amount * fillPercentage) / 100;
        
        // Transfer tokens to resolver
        IERC20(escrow.token).safeTransfer(escrow.resolver, fillAmount);

        emit FillExecuted(intentHash, fillPercentage, secret, msg.sender);

        // Check if escrow is completed
        if (escrow.totalFillPercentage == MAX_FILL_PERCENTAGE) {
            escrow.executed = true;
            // Return safety deposit to resolver
            payable(escrow.resolver).transfer(escrow.safetyDeposit);
            emit EscrowCompleted(intentHash);
        }
    }

    function cancelEscrow(bytes32 intentHash) external nonReentrant {
        EscrowData storage escrow = escrows[intentHash];
        require(escrow.user != address(0), "Escrow does not exist");
        require(!escrow.executed && !escrow.cancelled, "Escrow not active");
        require(
            block.timestamp > escrow.deadline || msg.sender == escrow.user || msg.sender == escrow.resolver,
            "Cannot cancel yet"
        );

        escrow.cancelled = true;

        // Refund remaining tokens to user
        uint256 remainingAmount = escrow.amount - (escrow.amount * escrow.totalFillPercentage) / 100;
        if (remainingAmount > 0) {
            IERC20(escrow.token).safeTransfer(escrow.user, remainingAmount);
        }

        // Return safety deposit to resolver
        payable(escrow.resolver).transfer(escrow.safetyDeposit);

        emit EscrowCancelled(intentHash);
    }

    function calculateSafetyDeposit(uint256 amount) public pure returns (uint256) {
        // Simplified calculation - in production, use oracle for token prices
        return (amount * MIN_SAFETY_DEPOSIT_PERCENTAGE) / 100;
    }

    function getEscrowData(bytes32 intentHash) external view returns (EscrowData memory) {
        return escrows[intentHash];
    }

    function getFillData(bytes32 intentHash, uint8 percentage) external view returns (FillData memory) {
        return fills[intentHash][percentage];
    }
}




module cross_chain::escrow {
    use sui::object::{Self, UID, ID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::coin::{Self, Coin};
    use sui::clock::{Self, Clock};
    use sui::event;
    use sui::table::{Self, Table};
    use std::vector;
    use std::string::{Self, String};

    // Error codes
    const EInvalidAmount: u64 = 1;
    const EEscrowNotExists: u64 = 2;
    const EEscrowExpired: u64 = 3;
    const EEscrowNotActive: u64 = 4;
    const EInvalidFillPercentage: u64 = 5;
    const EFillAlreadyExecuted: u64 = 6;
    const EInvalidMerkleProof: u64 = 7;
    const EExceedsMaxFill: u64 = 8;
    const ECannotCancel: u64 = 9;
    const EInsufficientSafetyDeposit: u64 = 10;

    // Main escrow object
    public struct Escrow<phantom T> has key, store {
        id: UID,
        user: address,
        resolver: address,
        locked_coin: Coin<T>,
        safety_deposit: Coin<SUI>,
        secret_commitment: vector<u8>, // Merkle root
        deadline: u64,
        destination_chain_id: u64,
        executed: bool,
        cancelled: bool,
        total_fill_percentage: u8,
    }

    // Registry to track all escrows
    public struct EscrowRegistry has key {
        id: UID,
        escrows: Table<vector<u8>, ID>, // intentHash -> escrow ID
        authorized_resolvers: Table<address, bool>,
        admin: address,
    }

    // Fill tracking
    public struct FillRecord has store {
        percentage: u8,
        secret: vector<u8>,
        executed: bool,
    }

    public struct EscrowFills has key {
        id: UID,
        escrow_id: ID,
        fills: Table<u8, FillRecord>, // percentage -> fill record
    }

    // Events
    public struct EscrowCreated has copy, drop {
        intent_hash: vector<u8>,
        escrow_id: ID,
        user: address,
        resolver: address,
        amount: u64,
        secret_commitment: vector<u8>,
        deadline: u64,
        destination_chain_id: u64,
    }

    public struct FillExecuted has copy, drop {
        intent_hash: vector<u8>,
        escrow_id: ID,
        percentage: u8,
        secret: vector<u8>,
        executor: address,
    }

    public struct EscrowCompleted has copy, drop {
        intent_hash: vector<u8>,
        escrow_id: ID,
    }

    public struct EscrowCancelled has copy, drop {
        intent_hash: vector<u8>,
        escrow_id: ID,
    }

    // Initialize registry
    fun init(ctx: &mut TxContext) {
        let registry = EscrowRegistry {
            id: object::new(ctx),
            escrows: table::new<vector<u8>, ID>(ctx),
            authorized_resolvers: table::new<address, bool>(ctx),
            admin: tx_context::sender(ctx),
        };
        transfer::share_object(registry);
    }

    // Admin functions
    public fun authorize_resolver(
        registry: &mut EscrowRegistry,
        resolver: address,
        ctx: &mut TxContext
    ) {
        assert!(tx_context::sender(ctx) == registry.admin, 0);
        table::add(&mut registry.authorized_resolvers, resolver, true);
    }

    // Create escrow
    public fun create_escrow<T>(
        registry: &mut EscrowRegistry,
        intent_hash: vector<u8>,
        user: address,
        coin: Coin<T>,
        safety_deposit: Coin<SUI>,
        secret_commitment: vector<u8>,
        deadline: u64,
        destination_chain_id: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let resolver = tx_context::sender(ctx);
        
        // Verify resolver authorization
        assert!(table::contains(&registry.authorized_resolvers, resolver), 0);
        assert!(!table::contains(&registry.escrows, intent_hash), EEscrowNotExists);
        assert!(deadline > clock::timestamp_ms(clock), EEscrowExpired);
        assert!(coin::value(&coin) > 0, EInvalidAmount);
        
        // Verify safety deposit (simplified - in production use price oracle)
        let required_deposit = coin::value(&coin) * 11 / 10; // 110%
        assert!(coin::value(&safety_deposit) >= required_deposit, EInsufficientSafetyDeposit);

        let escrow_id = object::new(ctx);
        let escrow_id_copy = object::uid_to_inner(&escrow_id);

        let escrow = Escrow<T> {
            id: escrow_id,
            user,
            resolver,
            locked_coin: coin,
            safety_deposit,
            secret_commitment,
            deadline,
            destination_chain_id,
            executed: false,
            cancelled: false,
            total_fill_percentage: 0,
        };

        // Create fill tracking
        let fills = EscrowFills {
            id: object::new(ctx),
            escrow_id: escrow_id_copy,
            fills: table::new<u8, FillRecord>(ctx),
        };

        // Register escrow
        table::add(&mut registry.escrows, intent_hash, escrow_id_copy);

        // Emit event
        event::emit(EscrowCreated {
            intent_hash,
            escrow_id: escrow_id_copy,
            user,
            resolver,
            amount: coin::value(&escrow.locked_coin),
            secret_commitment,
            deadline,
            destination_chain_id,
        });

        transfer::share_object(escrow);
        transfer::share_object(fills);
    }

    // Execute fill
    public fun execute_fill<T>(
        escrow: &mut Escrow<T>,
        fills: &mut EscrowFills,
        intent_hash: vector<u8>,
        fill_percentage: u8,
        secret: vector<u8>,
        merkle_proof: vector<vector<u8>>,
        clock: &Clock,
        ctx: &mut TxContext
    ): Coin<T> {
        assert!(!escrow.executed && !escrow.cancelled, EEscrowNotActive);
        assert!(clock::timestamp_ms(clock) <= escrow.deadline, EEscrowExpired);
        assert!(fill_percentage > 0 && fill_percentage <= 25, EInvalidFillPercentage);
        assert!(escrow.total_fill_percentage + fill_percentage <= 100, EExceedsMaxFill);
        assert!(!table::contains(&fills.fills, fill_percentage), EFillAlreadyExecuted);

        // Verify merkle proof (simplified - implement full merkle verification)
        let leaf = hash_leaf(fill_percentage, secret);
        assert!(verify_merkle_proof(leaf, merkle_proof, escrow.secret_commitment), EInvalidMerkleProof);

        // Record fill
        let fill_record = FillRecord {
            percentage: fill_percentage,
            secret,
            executed: true,
        };
        table::add(&mut fills.fills, fill_percentage, fill_record);

        escrow.total_fill_percentage = escrow.total_fill_percentage + fill_percentage;

        // Calculate fill amount
        let total_amount = coin::value(&escrow.locked_coin);
        let fill_amount = (total_amount * (fill_percentage as u64)) / 100;
        let filled_coin = coin::split(&mut escrow.locked_coin, fill_amount, ctx);

        // Emit event
        event::emit(FillExecuted {
            intent_hash,
            escrow_id: object::id(escrow),
            percentage: fill_percentage,
            secret,
            executor: tx_context::sender(ctx),
        });

        // Check if completed
        if (escrow.total_fill_percentage == 100) {
            escrow.executed = true;
            // Transfer safety deposit back to resolver
            let safety_amount = coin::value(&escrow.safety_deposit);
            let safety_coin = coin::split(&mut escrow.safety_deposit, safety_amount, ctx);
            transfer::public_transfer(safety_coin, escrow.resolver);
            
            event::emit(EscrowCompleted {
                intent_hash,
                escrow_id: object::id(escrow),
            });
        };

        filled_coin
    }

    // Cancel escrow
    public fun cancel_escrow<T>(
        escrow: &mut Escrow<T>,
        intent_hash: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext
    ): (Coin<T>, Coin<SUI>) {
        let sender = tx_context::sender(ctx);
        assert!(!escrow.executed && !escrow.cancelled, EEscrowNotActive);
        assert!(
            clock::timestamp_ms(clock) > escrow.deadline || 
            sender == escrow.user || 
            sender == escrow.resolver,
            ECannotCancel
        );

        escrow.cancelled = true;

        // Calculate remaining amount
        let total_amount = coin::value(&escrow.locked_coin);
        let filled_amount = (total_amount * (escrow.total_fill_percentage as u64)) / 100;
        let remaining_amount = total_amount - filled_amount;

        // Extract remaining coins
        let remaining_coin = if (remaining_amount > 0) {
            coin::split(&mut escrow.locked_coin, remaining_amount, ctx)
        } else {
            coin::zero<T>(ctx)
        };

        // Extract safety deposit
        let safety_amount = coin::value(&escrow.safety_deposit);
        let safety_coin = coin::split(&mut escrow.safety_deposit, safety_amount, ctx);

        event::emit(EscrowCancelled {
            intent_hash,
            escrow_id: object::id(escrow),
        });

        (remaining_coin, safety_coin)
    }

    // Helper functions
    fun hash_leaf(percentage: u8, secret: vector<u8>): vector<u8> {
        use sui::hash;
        let mut data = vector::empty<u8>();
        vector::push_back(&mut data, percentage);
        vector::append(&mut data, secret);
        hash::keccak256(&data)
    }

    fun verify_merkle_proof(
        leaf: vector<u8>,
        proof: vector<vector<u8>>,
        root: vector<u8>
    ): bool {
        // Simplified merkle proof verification
        // In production, implement full merkle tree verification
        let mut computed_hash = leaf;
        let mut i = 0;
        while (i < vector::length(&proof)) {
            let proof_element = *vector::borrow(&proof, i);
            computed_hash = hash_pair(computed_hash, proof_element);
            i = i + 1;
        };
        computed_hash == root
    }

    fun hash_pair(a: vector<u8>, b: vector<u8>): vector<u8> {
        use sui::hash;
        let mut data = vector::empty<u8>();
        if (compare_bytes(&a, &b)) {
            vector::append(&mut data, a);
            vector::append(&mut data, b);
        } else {
            vector::append(&mut data, b);
            vector::append(&mut data, a);
        };
        hash::keccak256(&data)
    }

    fun compare_bytes(a: &vector<u8>, b: &vector<u8>): bool {
        // Simple byte comparison for ordering
        let len_a = vector::length(a);
        let len_b = vector::length(b);
        if (len_a != len_b) {
            return len_a < len_b
        };
        let mut i = 0;
        while (i < len_a) {
            let byte_a = *vector::borrow(a, i);
            let byte_b = *vector::borrow(b, i);
            if (byte_a != byte_b) {
                return byte_a < byte_b
            };
            i = i + 1;
        };
        false
    }

    // View functions
    public fun get_escrow_info<T>(escrow: &Escrow<T>): (address, address, u64, vector<u8>, u64, u64, bool, bool, u8) {
        (
            escrow.user,
            escrow.resolver,
            coin::value(&escrow.locked_coin),
            escrow.secret_commitment,
            escrow.deadline,
            escrow.destination_chain_id,
            escrow.executed,
            escrow.cancelled,
            escrow.total_fill_percentage
        )
    }
}



import { ethers } from 'ethers';
import { SuiClient, getFullnodeUrl } from '@mysten/sui.js/client';
import { Ed25519Keypair } from '@mysten/sui.js/keypairs/ed25519';
import { TransactionBlock } from '@mysten/sui.js/transactions';
import { MerkleTree } from 'merkletreejs';
import crypto from 'crypto';

interface SwapIntent {
  user: string;
  sourceChain: 'ethereum' | 'sui';
  destChain: 'ethereum' | 'sui';
  sourceToken: string;
  destToken: string;
  amount: string;
  minReturn: string;
  deadline: number;
  nonce: number;
  secretCommitment: string;
  signature: string;
}

interface ResolverConfig {
  ethRpcUrl: string;
  suiRpcUrl: string;
  ethPrivateKey: string;
  suiPrivateKey: string;
  ethEscrowAddress: string;
  suiPackageId: string;
  minProfitMargin: number;
}

export class BasicResolver {
  private ethProvider: ethers.Provider;
  private ethSigner: ethers.Wallet;
  private suiClient: SuiClient;
  private suiKeypair: Ed25519Keypair;
  private config: ResolverConfig;
  private isRunning: boolean = false;

  constructor(config: ResolverConfig) {
    this.config = config;
    this.ethProvider = new ethers.JsonRpcProvider(config.ethRpcUrl);
    this.ethSigner = new ethers.Wallet(config.ethPrivateKey, this.ethProvider);
    this.suiClient = new SuiClient({ url: config.suiRpcUrl });
    this.suiKeypair = Ed25519Keypair.fromSecretKey(
      Buffer.from(config.suiPrivateKey, 'hex')
    );
  }

  async start() {
    console.log('Starting Basic Resolver...');
    this.isRunning = true;
    
    // Start monitoring for new intents
    this.monitorIntents();
    
    console.log('Resolver is running');
  }

  async stop() {
    this.isRunning = false;
    console.log('Resolver stopped');
  }

  private async monitorIntents() {
    while (this.isRunning) {
      try {
        // Check for new intents from your API/database
        const newIntents = await this.fetchNewIntents();
        
        for (const intent of newIntents) {
          if (await this.shouldResolveIntent(intent)) {
            await this.resolveIntent(intent);
          }
        }
        
        // Wait before next check
        await new Promise(resolve => setTimeout(resolve, 5000));
      } catch (error) {
        console.error('Error monitoring intents:', error);
        await new Promise(resolve => setTimeout(resolve, 10000));
      }
    }
  }

  private async fetchNewIntents(): Promise<SwapIntent[]> {
    // In production, fetch from your backend API
    // For now, return empty array
    return [];
  }

  private async shouldResolveIntent(intent: SwapIntent): Promise<boolean> {
    try {
      // Check if intent is profitable
      const quote = await this.getQuote(intent);
      const profit = parseFloat(quote.outputAmount) - parseFloat(intent.minReturn);
      const profitMargin = profit / parseFloat(intent.minReturn);
      
      return profitMargin >= this.config.minProfitMargin;
    } catch (error) {
      console.error('Error checking profitability:', error);
      return false;
    }
  }

  private async getQuote(intent: SwapIntent): Promise<{ outputAmount: string }> {
    // Simplified quote logic - in production, use DEX aggregators
    if (intent.sourceChain === 'ethereum' && intent.destChain === 'sui') {
      // ETH -> SUI quote
      return { outputAmount: (parseFloat(intent.amount) * 0.95).toString() };
    } else {
      // SUI -> ETH quote
      return { outputAmount: (parseFloat(intent.amount) * 0.95).toString() };
    }
  }

  async resolveIntent(intent: SwapIntent) {
    console.log(`Resolving intent: ${JSON.stringify(intent)}`);
    
    try {
      // Generate secrets for partial fills
      const secrets = this.generateSecrets();
      const merkleTree = this.createMerkleTree(secrets);
      
      // Deploy escrows on both chains
      if (intent.sourceChain === 'ethereum') {
        await this.deployEthToSuiEscrows(intent, merkleTree.getRoot(), secrets);
      } else {
        await this.deploySuiToEthEscrows(intent, merkleTree.getRoot(), secrets);
      }
      
      console.log(`Intent resolved successfully`);
    } catch (error) {
      console.error('Error resolving intent:', error);
    }
  }

  private generateSecrets(): Buffer[] {
    // Generate 4 secrets for 25% fills each
    return Array(4).fill(0).map(() => crypto.randomBytes(32));
  }

  private createMerkleTree(secrets: Buffer[]): MerkleTree {
    const leaves = secrets.map((secret, index) => {
      const percentage = 25; // Each fill is 25%
      return ethers.keccak256(
        ethers.concat([
          ethers.toBeHex(percentage, 1),
          ethers.keccak256(secret)
        ])
      );
    });
    
    return new MerkleTree(leaves, ethers.keccak256, { sortPairs: true });
  }

  private async deployEthToSuiEscrows(
    intent: SwapIntent,
    merkleRoot: Buffer,
    secrets: Buffer[]
  ) {
    // Deploy Ethereum source escrow
    const ethEscrow = new ethers.Contract(
      this.config.ethEscrowAddress,
      this.getEthEscrowABI(),
      this.ethSigner
    );

    const intentHash = this.calculateIntentHash(intent);
    const safetyDeposit = ethers.parseEther('0.1'); // Simplified

    const ethTx = await ethEscrow.createEscrow(
      intentHash,
      intent.user,
      intent.sourceToken,
      intent.amount,
      '0x' + merkleRoot.toString('hex'),
      intent.deadline,
      1, // Sui chain ID
      { value: safetyDeposit }
    );

    await ethTx.wait();
    console.log(`Ethereum escrow created: ${ethTx.hash}`);

    // Deploy Sui destination escrow
    await this.deploySuiEscrow(intent, merkleRoot, intentHash);
  }

  private async deploySuiToEthEscrows(
    intent: SwapIntent,
    merkleRoot: Buffer,
    secrets: Buffer[]
  ) {
    // Similar to deployEthToSuiEscrows but reversed
    // Implementation details...
  }

  private async deploySuiEscrow(
    intent: SwapIntent,
    merkleRoot: Buffer,
    intentHash: string
  ) {
    const txb = new TransactionBlock();
    
    // Create coin for destination tokens
    const coin = txb.splitCoins(txb.gas, [txb.pure(intent.minReturn)]);
    
    // Create safety deposit
    const safetyDeposit = txb.splitCoins(txb.gas, [txb.pure(100_000_000)]); // 0.1 SUI
    
    txb.moveCall({
      target: `${this.config.suiPackageId}::escrow::create_escrow`,
      typeArguments: ['0x2::sui::SUI'],
      arguments: [
        txb.object('REGISTRY_ID'), // Replace with actual registry ID
        txb.pure(Array.from(Buffer.from(intentHash.slice(2), 'hex'))),
        txb.pure(intent.user),
        coin,
        safetyDeposit,
        txb.pure(Array.from(merkleRoot)),
        txb.pure(intent.deadline),
        txb.pure(1), // Ethereum chain ID
      ]
    });

    const result = await this.suiClient.signAndExecuteTransactionBlock({
      signer: this.suiKeypair,
      transactionBlock: txb,
    });

    console.log(`Sui escrow created: ${result.digest}`);
  }

  private calculateIntentHash(intent: SwapIntent): string {
    return ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ['address', 'string', 'string', 'string', 'string', 'string', 'string', 'uint256', 'uint256'],
        [
          intent.user,
          intent.sourceChain,
          intent.destChain,
          intent.sourceToken,
          intent.destToken,
          intent.amount,
          intent.minReturn,
          intent.deadline,
          intent.nonce
        ]
      )
    );
  }

  private getEthEscrowABI() {
    // Return the contract ABI
    return [
      'function createEscrow(bytes32 intentHash, address user, address token, uint256 amount, bytes32 secretCommitment, uint256 deadline, uint256 destinationChainId) external payable',
      'function executeFill(bytes32 intentHash, uint8 fillPercentage, bytes32 secret, bytes32[] calldata merkleProof) external',
      'function cancelEscrow(bytes32 intentHash) external'
    ];
  }
}

// Usage example
const resolverConfig: ResolverConfig = {
  ethRpcUrl: 'https://sepolia.infura.io/v3/YOUR_KEY',
  suiRpcUrl: getFullnodeUrl('testnet'),
  ethPrivateKey: process.env.ETH_PRIVATE_KEY!,
  suiPrivateKey: process.env.SUI_PRIVATE_KEY!,
  ethEscrowAddress: '0x...', // Deploy address
  suiPackageId: '0x...', // Package ID after deployment
  minProfitMargin: 0.01 // 1% minimum profit
};

const resolver = new BasicResolver(resolverConfig);

// Start resolver
resolver.start().catch(console.error);

// Graceful shutdown
process.on('SIGINT', async () => {
  await resolver.stop();
  process.exit(0);
});



