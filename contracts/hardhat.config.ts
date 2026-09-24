import { HardhatUserConfig, task } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@openzeppelin/hardhat-upgrades";

// `hardhat run` takes no custom params, so --contract has to be a task.
// Imported inside the action, after the runtime environment exists, because
// that module imports "hardhat".
task("deploy", "Deploy everything, or one registry with --contract")
  .addOptionalParam("contract", "Registry name, e.g. SignatureRegistry or SignatureRegistryV1")
  .setAction(async ({ contract }: { contract?: string }) => {
    const { deploy } = await import("./scripts/deploy-impl");
    await deploy({ contract });
  });

const explorerUrl = process.env.EXPLORER_URL;

const deployerAccounts = process.env.DEPLOYER_PRIVATE_KEY
  ? [process.env.DEPLOYER_PRIVATE_KEY]
  : [];

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
  // Network names are also the keys in chain/config.json, which assigns the
  // on-chain roles for a deployment. The two local networks are pinned to their
  // own port; both remote networks read the same RPC_URL, with no localhost
  // fallback, so `--network sovrachain` cannot quietly hit the local node and
  // grant the shared chain's roles there.
  networks: {
    anvil: {
      url: "http://127.0.0.1:8545",
    },
    // The local ethrex L2. Fixed at :1729 rather than reading RPC_URL, like
    // `anvil` at :8545: its chain/config.json entry puts every role on the
    // node's genesis account, which must never be aimed at a remote chain.
    ethrex: {
      url: "http://127.0.0.1:1729",
      accounts: deployerAccounts,
    },
    sovrachain: {
      url: process.env.RPC_URL || "",
      accounts: deployerAccounts,
    },
    "sovrachain-sepolia": {
      url: process.env.RPC_URL || "",
      accounts: deployerAccounts,
    },
  },
  // EXPLORER_URL / CHAIN_ID describe the one chain being verified against, so
  // both networks are listed with the same env-driven explorer.
  ...(explorerUrl && {
    etherscan: {
      apiKey: {
        sovrachain: process.env.EXPLORER_API_KEY || "empty",
        "sovrachain-sepolia": process.env.EXPLORER_API_KEY || "empty",
      },
      customChains: ["sovrachain", "sovrachain-sepolia"].map((network) => ({
        network,
        chainId: Number(process.env.CHAIN_ID || 0),
        urls: {
          apiURL: `${explorerUrl}/api`,
          browserURL: explorerUrl,
        },
      })),
    },
  }),
};

export default config;
