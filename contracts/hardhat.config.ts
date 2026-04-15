import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@openzeppelin/hardhat-upgrades";

const explorerUrl = process.env.EXPLORER_URL;

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.31",
    settings: {
      optimizer: {
        enabled: true,
        runs: 10000,
      },
      evmVersion: "osaka",
    },
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
  },
  networks: {
    localhost: {
      url: "http://127.0.0.1:8545",
    },
    l2: {
      url: process.env.ETHREX_L2_RPC || "http://127.0.0.1:1729",
      accounts: process.env.DEPLOYER_PRIVATE_KEY
        ? [process.env.DEPLOYER_PRIVATE_KEY]
        : [],
    },
  },
  ...(explorerUrl && {
    etherscan: {
      apiKey: {
        l2: process.env.EXPLORER_API_KEY || "empty",
      },
      customChains: [
        {
          network: "l2",
          chainId: Number(process.env.CHAIN_ID || 0),
          urls: {
            apiURL: `${explorerUrl}/api`,
            browserURL: explorerUrl,
          },
        },
      ],
    },
  }),
};

export default config;
