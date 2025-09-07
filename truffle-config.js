module.exports = {
  networks: {
    development: {
      host: "127.0.0.1",     // Ganache default
      port: 7545,            // Ganache GUI uses 7545, CLI uses 8545
      network_id: "*",       // Match any network id
    },
  },
  compilers: {
    solc: {
      version: "0.8.19",     // Match your Solidity version
    }
  }
};
