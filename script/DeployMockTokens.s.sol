// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script} from "forge-std/Script.sol";
import {MockERC20} from "../src/MockERC20.sol";

/// @notice Deploys two mock ERC20 tokens for testing
contract DeployMockTokensScript is Script {
    function run() public {
        vm.startBroadcast();

        // Deploy first token: USDC mock
        MockERC20 tokenA = new MockERC20(
            "Mock USDC",
            "mUSDC",
            6, // 6 decimals like real USDC
            1_000_000 * 10**6 // 1M tokens initial supply
        );

        // Deploy second token: WETH mock
        MockERC20 tokenB = new MockERC20(
            "Mock Wrapped Ether",
            "mWETH",
            18, // 18 decimals like real WETH
            10_000 * 10**18 // 10K tokens initial supply
        );

        vm.stopBroadcast();

        // Emit events with deployment info for logging
        emit TokenDeployed("mUSDC", address(tokenA), tokenA.decimals(), tokenA.totalSupply());
        emit TokenDeployed("mWETH", address(tokenB), tokenB.decimals(), tokenB.totalSupply());
    }

    event TokenDeployed(string name, address tokenAddress, uint8 decimals, uint256 totalSupply);
}