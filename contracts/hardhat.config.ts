import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

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
    ethrexL2: {
      url: process.env.ETHREX_L2_RPC || "http://127.0.0.1:1729",
    },
  },
};

export default config;
