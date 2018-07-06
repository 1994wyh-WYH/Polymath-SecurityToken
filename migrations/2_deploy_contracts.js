const ModuleRegistry = artifacts.require('ModuleRegistry')
const GeneralTransferManagerFactory = artifacts.require('GeneralTransferManagerFactory')
const GeneralPermissionManagerFactory = artifacts.require('GeneralPermissionManagerFactory')
const SecurityTokenRegistry = artifacts.require('SecurityTokenRegistry')
const TickerRegistry = artifacts.require('TickerRegistry')
const STVersionProxy001 = artifacts.require('STVersionProxy001')
const DevPolyToken = artifacts.require('PolyTokenFaucet')

let BigNumber = require('bignumber.js');
const cappedSTOSetupCost = new BigNumber(20000).times(new BigNumber(10).pow(18));   // 20K POLY fee
const initRegFee = new BigNumber(250).times(new BigNumber(10).pow(18));      // 250 POLY fee for registering ticker or security token in registry

let PolyToken
const Web3 = require('web3')

module.exports = function (deployer, network, accounts) {
  // Ethereum account address hold by the Polymath (Act as the main account which have ownable permissions)
  let PolymathAccount
  let web3
  if (network === 'development') {
    web3 = new Web3(new Web3.providers.HttpProvider('http://localhost:8545'))
    PolymathAccount = accounts[0]
    PolyToken = DevPolyToken.address // Development network polytoken address
  } 
}

// POLYMATH NETWORK Configuration :: DO THIS ONLY ONCE
  // A) Deploy the ModuleRegistry Contract (It contains the list of verified ModuleFactory)
  return deployer.deploy(ModuleRegistry, {from: PolymathAccount}).then(() => {
    return ModuleRegistry.deployed().then((moduleRegistry) => {
      // B) Deploy the GeneralTransferManagerFactory Contract (Factory used to generate the GeneralTransferManager contract and this
      // manager attach with the securityToken contract at the time of deployment)
    return deployer.deploy(GeneralTransferManagerFactory, PolyToken, 0, 0, 0, {from: PolymathAccount})
    .then(() => {
      // C) Deploy the GeneralPermissionManagerFactory Contract (Factory used to generate the GeneralPermissionManager contract and
      // this manager attach with the securityToken contract at the time of deployment)
    return deployer.deploy(GeneralPermissionManagerFactory, PolyToken, 0, 0, 0, {from: PolymathAccount})
    }).then(() => {
      // D) Register the GeneralTransferManagerFactory in the ModuleRegistry to make the factory available at the protocol level.
      // So any securityToken can use that factory to generate the GeneralTransferManager contract.
    return moduleRegistry.registerModule(GeneralTransferManagerFactory.address, {from: PolymathAccount})
    }).then(() => {
      // E) Register the GeneralPermissionManagerFactory in the ModuleRegistry to make the factory available at the protocol level.
      // So any securityToken can use that factory to generate the GeneralPermissionManager contract.
    return moduleRegistry.registerModule(GeneralPermissionManagerFactory.address, {from: PolymathAccount})
}).then(() => {
      // F) Once the GeneralTransferManagerFactory registered with the ModuleRegistry contract then for making them accessble to the securityToken
      // contract, Factory should comes under the verified list of factories or those factories deployed by the securityToken issuers only.
      // Here it gets verified because it is deployed by the third party account (Polymath Account) not with the issuer accounts.
    return moduleRegistry.verifyModule(GeneralTransferManagerFactory.address, true, {from: PolymathAccount})
    }).then(() => {
    // G) Once the GeneralPermissionManagerFactory registered with the ModuleRegistry contract then for making them accessble to the securityToken
      // contract, Factory should comes under the verified list of factories or those factories deployed by the securityToken issuers only.
      // Here it gets verified because it is deployed by the third party account (Polymath Account) not with the issuer accounts.
    return moduleRegistry.verifyModule(GeneralPermissionManagerFactory.address, true, {from: PolymathAccount})
    }).then(() => {
      // H) Deploy the STVersionProxy001 Contract which contains the logic of deployment of securityToken.
    return deployer.deploy(STVersionProxy001, GeneralTransferManagerFactory.address, {from: PolymathAccount})
    }).then(() => {
      // I) Deploy the TickerRegistry Contract (It is used to store the information about the ticker)
    return deployer.deploy(TickerRegistry, PolyToken, initRegFee, {from: PolymathAccount})
    }).then(() => {
      // J) Deploy the SecurityTokenRegistry contract (Used to hold the deployed secuirtyToken details. It also act as the interface to deploy the SecurityToken)
    return deployer.deploy(SecurityTokenRegistry, PolyToken, ModuleRegistry.address, TickerRegistry.address, STVersionProxy001.address, initRegFee, {from: PolymathAccount})
    }).then(() => {
    return TickerRegistry.deployed().then((tickerRegistry) => {
      // K) SecurityTokenRegistry address make available to the TickerRegistry contract for accessing the securityTokenRegistry functions
      return tickerRegistry.changeAddress("SecurityTokenRegistry", SecurityTokenRegistry.address, {from: PolymathAccount});
    }).then(() => {
      // L) SecurityTokenRegistry address make available to the TickerRegistry contract for accessing the securityTokenRegistry functions
    return moduleRegistry.changeAddress("SecurityTokenRegistry", SecurityTokenRegistry.address, {from: PolymathAccount});
    }).then(() => {
        console.log('\n')
        console.log('----- Polymath Core Contracts -----')
        console.log('*** Ticker Registry Address: ', TickerRegistry.address, '***')
        console.log('*** Module Registry Address: ', ModuleRegistry.address, '***')
        console.log('*** Security Token Registry Address: ', SecurityTokenRegistry.address, '***')
        console.log('*** General Permission Manager Factory: ', GeneralPermissionManagerFactory.address, '***')
        console.log('-----------------------------------')
        console.log('\n')
        // -------- END OF POLYMATH NETWORK Configuration -------//
    })
  })
})
})
}
