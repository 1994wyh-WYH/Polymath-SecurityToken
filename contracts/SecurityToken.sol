pragma solidity ^0.4.23;

/**
 * @title ERC20Basic
 * @dev Simpler version of ERC20 interface
 * @dev see https://github.com/ethereum/EIPs/issues/179
 */
contract ERC20Basic {
  function totalSupply() public view returns (uint256);
  function balanceOf(address who) public view returns (uint256);
  function transfer(address to, uint256 value) public returns (bool);
  event Transfer(address indexed from, address indexed to, uint256 value);
}

/**
 * @title ERC20 interface
 * @dev see https://github.com/ethereum/EIPs/issues/20
 */
contract ERC20 is ERC20Basic {
  function allowance(address owner, address spender) public view returns (uint256);
  function transferFrom(address from, address to, uint256 value) public returns (bool);
  function approve(address spender, uint256 value) public returns (bool);
  event Approval(address indexed owner, address indexed spender, uint256 value);
}

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {

  /**
  * @dev Multiplies two numbers, throws on overflow.
  */
  function mul(uint256 a, uint256 b) internal pure returns (uint256 c) {
    if (a == 0) {
      return 0;
    }
    c = a * b;
    assert(c / a == b);
    return c;
  }

  /**
  * @dev Integer division of two numbers, truncating the quotient.
  */
  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    // uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return a / b;
  }

  /**
  * @dev Subtracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
  */
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  /**
  * @dev Adds two numbers, throws on overflow.
  */
  function add(uint256 a, uint256 b) internal pure returns (uint256 c) {
    c = a + b;
    assert(c >= a);
    return c;
  }
}

/**
 * @title Math
 * @dev Assorted math operations
 */
library Math {
  function max64(uint64 a, uint64 b) internal pure returns (uint64) {
    return a >= b ? a : b;
  }

  function min64(uint64 a, uint64 b) internal pure returns (uint64) {
    return a < b ? a : b;
  }

  function max256(uint256 a, uint256 b) internal pure returns (uint256) {
    return a >= b ? a : b;
  }

  function min256(uint256 a, uint256 b) internal pure returns (uint256) {
    return a < b ? a : b;
  }
}

/**
 * @title Basic token
 * @dev Basic version of StandardToken, with no allowances.
 */
contract BasicToken is ERC20Basic {
  using SafeMath for uint256;

  mapping(address => uint256) balances;

  uint256 totalSupply_;

  /**
  * @dev total number of tokens in existence
  */
  function totalSupply() public view returns (uint256) {
    return totalSupply_;
  }

  /**
  * @dev transfer token for a specified address
  * @param _to The address to transfer to.
  * @param _value The amount to be transferred.
  */
  function transfer(address _to, uint256 _value) public returns (bool) {
    require(_to != address(0));
    require(_value <= balances[msg.sender]);

    balances[msg.sender] = balances[msg.sender].sub(_value);
    balances[_to] = balances[_to].add(_value);
    emit Transfer(msg.sender, _to, _value);
    return true;
  }

  /**
  * @dev Gets the balance of the specified address.
  * @param _owner The address to query the the balance of.
  * @return An uint256 representing the amount owned by the passed address.
  */
  function balanceOf(address _owner) public view returns (uint256) {
    return balances[_owner];
  }

}

/**
 * @title Standard ERC20 token
 *
 * @dev Implementation of the basic standard token.
 * @dev https://github.com/ethereum/EIPs/issues/20
 * @dev Based on code by FirstBlood: https://github.com/Firstbloodio/token/blob/master/smart_contract/FirstBloodToken.sol
 */
contract StandardToken is ERC20, BasicToken {

  mapping (address => mapping (address => uint256)) internal allowed;


  /**
   * @dev Transfer tokens from one address to another
   * @param _from address The address which you want to send tokens from
   * @param _to address The address which you want to transfer to
   * @param _value uint256 the amount of tokens to be transferred
   */
  function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
    require(_to != address(0));
    require(_value <= balances[_from]);
    require(_value <= allowed[_from][msg.sender]);

    balances[_from] = balances[_from].sub(_value);
    balances[_to] = balances[_to].add(_value);
    allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
    emit Transfer(_from, _to, _value);
    return true;
  }

  /**
   * @dev Approve the passed address to spend the specified amount of tokens on behalf of msg.sender.
   *
   * Beware that changing an allowance with this method brings the risk that someone may use both the old
   * and the new allowance by unfortunate transaction ordering. One possible solution to mitigate this
   * race condition is to first reduce the spender's allowance to 0 and set the desired value afterwards:
   * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
   * @param _spender The address which will spend the funds.
   * @param _value The amount of tokens to be spent.
   */
  function approve(address _spender, uint256 _value) public returns (bool) {
    allowed[msg.sender][_spender] = _value;
    emit Approval(msg.sender, _spender, _value);
    return true;
  }

  /**
   * @dev Function to check the amount of tokens that an owner allowed to a spender.
   * @param _owner address The address which owns the funds.
   * @param _spender address The address which will spend the funds.
   * @return A uint256 specifying the amount of tokens still available for the spender.
   */
  function allowance(address _owner, address _spender) public view returns (uint256) {
    return allowed[_owner][_spender];
  }

  /**
   * @dev Increase the amount of tokens that an owner allowed to a spender.
   *
   * approve should be called when allowed[_spender] == 0. To increment
   * allowed value is better to use this function to avoid 2 calls (and wait until
   * the first transaction is mined)
   * From MonolithDAO Token.sol
   * @param _spender The address which will spend the funds.
   * @param _addedValue The amount of tokens to increase the allowance by.
   */
  function increaseApproval(address _spender, uint _addedValue) public returns (bool) {
    allowed[msg.sender][_spender] = allowed[msg.sender][_spender].add(_addedValue);
    emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
    return true;
  }

  /**
   * @dev Decrease the amount of tokens that an owner allowed to a spender.
   *
   * approve should be called when allowed[_spender] == 0. To decrement
   * allowed value is better to use this function to avoid 2 calls (and wait until
   * the first transaction is mined)
   * From MonolithDAO Token.sol
   * @param _spender The address which will spend the funds.
   * @param _subtractedValue The amount of tokens to decrease the allowance by.
   */
  function decreaseApproval(address _spender, uint _subtractedValue) public returns (bool) {
    uint oldValue = allowed[msg.sender][_spender];
    if (_subtractedValue > oldValue) {
      allowed[msg.sender][_spender] = 0;
    } else {
      allowed[msg.sender][_spender] = oldValue.sub(_subtractedValue);
    }
    emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
    return true;
  }

}

contract DetailedERC20 is ERC20 {
  string public name;
  string public symbol;
  uint8 public decimals;

  function DetailedERC20(string _name, string _symbol, uint8 _decimals) public {
    name = _name;
    symbol = _symbol;
    decimals = _decimals;
  }
}

/**
 * @title Interface for the ST20 token standard
 */
contract IST20 is StandardToken, DetailedERC20 {

    // off-chain hash
    string public tokenDetails;

    //transfer, transferFrom must respect use respect the result of verifyTransfer
    function verifyTransfer(address _from, address _to, uint256 _amount) public returns (bool success);

    // used to create tokens
    function mint(address _investor, uint256 _amount) public returns (bool success);

    // used to burn the tokens
    function burn(uint256 _value) public;

    event Minted(address indexed to, uint256 amount);
    event Burnt(address indexed _burner, uint256 _value);

}

/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {
  address public owner;


  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);


  /**
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  function Ownable() public {
    owner = msg.sender;
  }

  /**
   * @dev Throws if called by any account other than the owner.
   */
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  /**
   * @dev Allows the current owner to transfer control of the contract to a newOwner.
   * @param newOwner The address to transfer ownership to.
   */
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    emit OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }

}

/**
 * @title Mintable token
 * @dev Simple ERC20 Token example, with mintable token creation
 * Based on code by TokenMarketNet: https://github.com/TokenMarketNet/ico/blob/master/contracts/MintableToken.sol
 */
contract MintableToken is StandardToken, Ownable {
  event Mint(address indexed to, uint256 amount);
  event MintFinished();

  bool public mintingFinished = false;


  modifier canMint() {
    require(!mintingFinished);
    _;
  }

  modifier hasMintPermission() {
    require(msg.sender == owner);
    _;
  }

  /**
   * @dev Function to mint tokens
   * @param _to The address that will receive the minted tokens.
   * @param _amount The amount of tokens to mint.
   * @return A boolean that indicates if the operation was successful.
   */
  function mint(
    address _to,
    uint256 _amount
  )
    hasMintPermission
    canMint
    public
    returns (bool)
  {
    totalSupply_ = totalSupply_.add(_amount);
    balances[_to] = balances[_to].add(_amount);
    emit Mint(_to, _amount);
    emit Transfer(address(0), _to, _amount);
    return true;
  }

  /**
   * @dev Function to stop minting new tokens.
   * @return True if the operation was successful.
   */
  function finishMinting() onlyOwner canMint public returns (bool) {
    mintingFinished = true;
    emit MintFinished();
    return true;
  }
}

/**
 * @title Utility contract to allow pausing and unpausing of certain functions
 */
contract Pausable {

    event Pause(uint256 _timestammp);
    event Unpause(uint256 _timestamp);

    bool public paused = false;

    /**
    * @notice Modifier to make a function callable only when the contract is not paused.
    */
    modifier whenNotPaused() {
        require(!paused);
        _;
    }

    /**
    * @notice Modifier to make a function callable only when the contract is paused.
    */
    modifier whenPaused() {
        require(paused);
        _;
    }

   /**
    * @notice called by the owner to pause, triggers stopped state
    */
    function _pause() internal {
        require(!paused);
        paused = true;
        emit Pause(now);
    }

    /**
    * @notice called by the owner to unpause, returns to normal state
    */
    function _unpause() internal {
        require(paused);
        paused = false;
        emit Unpause(now);
    }

}

/**
 * @title Interface for all polymath registry contracts
 */
contract IRegistry {

    /**
     * @notice get the contract address
     * @param _nameKey is the key for the contract address mapping
     */
    function getAddress(string _nameKey) view public returns(address);

    /**
     * @notice change the contract address
     * @param _nameKey is the key for the contract address mapping
     * @param _newAddress is the new contract address
     */
    function changeAddress(string _nameKey, address _newAddress) public;

    /**
     * @notice pause (overridden function)
     */
    function unpause() public;

    /**
     * @notice unpause (overridden function)
     */
    function pause() public;

}

/*
 POLY token faucet is only used on testnet for testing purposes
 !!!! NOT INTENDED TO BE USED ON MAINNET !!!
*/

contract PolyTokenFaucet {

    using SafeMath for uint256;
    uint256 totalSupply_ = 1000000;
    string public name = "Polymath Network";
    uint8 public decimals = 18;
    string public symbol = "POLY";

    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowed;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    /* Token faucet - Not part of the ERC20 standard */
    function getTokens(uint256 _amount, address _recipient) public returns (bool) {
        balances[_recipient] += _amount;
        totalSupply_ += _amount;
        return true;
    }

    /**
     * @notice send `_value` token to `_to` from `msg.sender`
     * @param _to The address of the recipient
     * @param _value The amount of token to be transferred
     * @return Whether the transfer was successful or not
     */
    function transfer(address _to, uint256 _value) public returns (bool) {
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    /**
     * @notice send `_value` token to `_to` from `_from` on the condition it is approved by `_from`
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value The amount of token to be transferred
     * @return Whether the transfer was successful or not
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        require(_to != address(0));
        require(_value <= balances[_from]);
        require(_value <= allowed[_from][msg.sender]);

        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    /**
     * @notice `balanceOf` function to get the balance of token holders
     * @param _owner The address from which the balance will be retrieved
     * @return The balance
     */
    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    /**
     * @notice `msg.sender` approves `_spender` to spend `_value` tokens
     * @param _spender The address of the account able to transfer the tokens
     * @param _value The amount of tokens to be approved for transfer
     * @return Whether the approval was successful or not
     */
    function approve(address _spender, uint256 _value) public returns (bool) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    /**
     * @param _owner The address of the account owning tokens
     * @param _spender The address of the account able to transfer the tokens
     * @return Amount of remaining tokens allowed to spent
     */
    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    function totalSupply() public view returns (uint256) {
        return totalSupply_;
    }

}

/**
 * @title Interface for all security tokens
 */
contract ISecurityToken is IST20, Ownable {

    uint8 public constant PERMISSIONMANAGER_KEY = 1;
    uint8 public constant TRANSFERMANAGER_KEY = 2;
    uint8 public constant STO_KEY = 3;
    uint8 public constant CHECKPOINT_KEY = 4;
    uint256 public granularity;

    // Value of current checkpoint
    uint256 public currentCheckpointId;

    // Total number of non-zero token holders
    uint256 public investorCount;

    // List of token holders
    address[] public investors;

    // Permissions this to a Permission module, which has a key of 1
    // If no Permission return false - note that IModule withPerm will allow ST owner all permissions anyway
    // this allows individual modules to override this logic if needed (to not allow ST owner all permissions)
    function checkPermission(address _delegate, address _module, bytes32 _perm) public view returns(bool);

    /**
     * @notice returns module list for a module type
     * @param _moduleType is which type of module we are trying to remove
     * @param _moduleIndex is the index of the module within the chosen type
     */
    function getModule(uint8 _moduleType, uint _moduleIndex) public returns (bytes32, address);

    /**
     * @notice returns module list for a module name - will return first match
     * @param _moduleType is which type of module we are trying to remove
     * @param _name is the name of the module within the chosen type
     */
    function getModuleByName(uint8 _moduleType, bytes32 _name) public returns (bytes32, address);

    /**
     * @notice Queries totalSupply as of a defined checkpoint
     * @param _checkpointId Checkpoint ID to query as of
     */
    function totalSupplyAt(uint256 _checkpointId) public view returns(uint256);

    /**
     * @notice Queries balances as of a defined checkpoint
     * @param _investor Investor to query balance for
     * @param _checkpointId Checkpoint ID to query as of
     */
    function balanceOfAt(address _investor, uint256 _checkpointId) public view returns(uint256);

    /**
     * @notice Creates a checkpoint that can be used to query historical balances / totalSuppy
     */
    function createCheckpoint() public returns(uint256);

    /**
     * @notice gets length of investors array
     * NB - this length may differ from investorCount if list has not been pruned of zero balance investors
     * @return length
     */
    function getInvestorsLength() public view returns(uint256);

}

/**
 * @title Interface that any module factory contract should implement
 */
contract IModuleFactory is Ownable {

    ERC20 public polyToken;
    uint256 public setupCost;
    uint256 public usageCost;
    uint256 public monthlySubscriptionCost;

    event LogChangeFactorySetupFee(uint256 _oldSetupcost, uint256 _newSetupCost, address _moduleFactory);
    event LogChangeFactoryUsageFee(uint256 _oldUsageCost, uint256 _newUsageCost, address _moduleFactory);
    event LogChangeFactorySubscriptionFee(uint256 _oldSubscriptionCost, uint256 _newMonthlySubscriptionCost, address _moduleFactory);
    event LogGenerateModuleFromFactory(address _module, bytes32 indexed _moduleName, address indexed _moduleFactory, address _creator, uint256 _timestamp);

    /**
     * @notice Constructor
     * @param _polyAddress Address of the polytoken
     */
    constructor (address _polyAddress, uint256 _setupCost, uint256 _usageCost, uint256 _subscriptionCost) public {
      polyToken = ERC20(_polyAddress);
      setupCost = _setupCost;
      usageCost = _usageCost;
      monthlySubscriptionCost = _subscriptionCost;
    }

    //Should create an instance of the Module, or throw
    function deploy(bytes _data) external returns(address);

    /**
     * @notice Type of the Module factory
     */
    function getType() public view returns(uint8);

    /**
     * @notice Get the name of the Module
     */
    function getName() public view returns(bytes32);

    /**
     * @notice Get the description of the Module
     */
    function getDescription() public view returns(string);

    /**
     * @notice Get the title of the Module
     */
    function getTitle() public view returns(string);

    /**
     * @notice Get the Instructions that helped to used the module
     */
    function getInstructions() public view returns (string);

    /**
     * @notice Get the tags related to the module factory
     */
    function getTags() public view returns (bytes32[]);

    //Pull function sig from _data
    function getSig(bytes _data) internal pure returns (bytes4 sig) {
        uint len = _data.length < 4 ? _data.length : 4;
        for (uint i = 0; i < len; i++) {
            sig = bytes4(uint(sig) + uint(_data[i]) * (2 ** (8 * (len - 1 - i))));
        }
    }

    /**
     * @notice used to change the fee of the setup cost
     * @param _newSetupCost new setup cost
     */
    function changeFactorySetupFee(uint256 _newSetupCost) public onlyOwner {
        uint256 _oldSetupcost = setupCost;
        setupCost = _newSetupCost;
        emit LogChangeFactorySetupFee(_oldSetupcost, setupCost, address(this));
    }

    /**
     * @notice used to change the fee of the usage cost
     * @param _newUsageCost new usage cost
     */
    function changeFactoryUsageFee(uint256 _newUsageCost) public onlyOwner {
        uint256 _oldUsageCost = usageCost;
        usageCost = _newUsageCost;
        emit LogChangeFactoryUsageFee(_oldUsageCost, usageCost, address(this));
    }

    /**
     * @notice used to change the fee of the subscription cost
     * @param _newSubscriptionCost new subscription cost
     */
    function changeFactorySubscriptionFee(uint256 _newSubscriptionCost) public onlyOwner {
        uint256 _oldSubscriptionCost = monthlySubscriptionCost;
        monthlySubscriptionCost = _newSubscriptionCost;
        emit LogChangeFactorySubscriptionFee(_oldSubscriptionCost, monthlySubscriptionCost, address(this));
    }

}

/**
 * @title Interface that any module contract should implement
 */
contract IModule {

    address public factory;

    address public securityToken;

    bytes32 public FEE_ADMIN = "FEE_ADMIN";

    ERC20 public polyToken;

    /**
     * @notice Constructor
     * @param _securityToken Address of the security token
     * @param _polyAddress Address of the polytoken
     */
    constructor (address _securityToken, address _polyAddress) public {
        securityToken = _securityToken;
        factory = msg.sender;
        polyToken = ERC20(_polyAddress);
    }

    /**
     * @notice This function returns the signature of configure function
     */
    function getInitFunction() public returns (bytes4);

    //Allows owner, factory or permissioned delegate
    modifier withPerm(bytes32 _perm) {
        bool isOwner = msg.sender == ISecurityToken(securityToken).owner();
        bool isFactory = msg.sender == factory;
        require(isOwner||isFactory||ISecurityToken(securityToken).checkPermission(msg.sender, address(this), _perm), "Permission check failed");
        _;
    }

    modifier onlyOwner {
        require(msg.sender == ISecurityToken(securityToken).owner(), "Sender is not owner");
        _;
    }

    modifier onlyFactory {
        require(msg.sender == factory, "Sender is not factory");
        _;
    }

    modifier onlyFactoryOwner {
        require(msg.sender == IModuleFactory(factory).owner(), "Sender is not factory owner");
        _;
    }

    /**
     * @notice Return the permissions flag that are associated with Module
     */
    function getPermissions() public view returns(bytes32[]);

    /**
     * @notice used to withdraw the fee by the factory owner
     */
    function takeFee(uint256 _amount) public withPerm(FEE_ADMIN) returns(bool) {
        require(polyToken.transferFrom(address(this), IModuleFactory(factory).owner(), _amount), "Unable to take fee");
        return true;
    }
}

/**
 * @title Interface for the polymath module registry contract
 */
contract IModuleRegistry {

    /**
     * @notice Called by a security token to notify the registry it is using a module
     * @param _moduleFactory is the address of the relevant module factory
     */
    function useModule(address _moduleFactory) external;

    /**
     * @notice Called by moduleFactory owner to register new modules for SecurityToken to use
     * @param _moduleFactory is the address of the module factory to be registered
     */
    function registerModule(address _moduleFactory) external returns(bool);

    /**
     * @notice Use to get all the tags releated to the functionality of the Module Factory.
     * @param _moduleType Type of module
     */
    function getTagByModuleType(uint8 _moduleType) public view returns(bytes32[]);

}

/**
 * @title Interface to be implemented by all Transfer Manager modules
 */
contract ITransferManager is IModule, Pausable {

    //If verifyTransfer returns:
    //  FORCE_VALID, the transaction will always be valid, regardless of other TM results
    //  INVALID, then the transfer should not be allowed regardless of other TM results
    //  VALID, then the transfer is valid for this TM
    //  NA, then the result from this TM is ignored
    enum Result {INVALID, NA, VALID, FORCE_VALID}

    function verifyTransfer(address _from, address _to, uint256 _amount, bool _isTransfer) public returns(Result);

    function unpause() onlyOwner public {
        super._unpause();
    }

    function pause() onlyOwner public {
        super._pause();
    }
}

/**
 * @title Interface to be implemented by all permission manager modules
 */
contract IPermissionManager is IModule {

    function checkPermission(address _delegate, address _module, bytes32 _perm) public view returns(bool);

    function changePermission(address _delegate, address _module, bytes32 _perm, bool _valid) public returns(bool);

    function getDelegateDetails(address _delegate) public view returns(bytes32);

}

/**
 * @title Interface for the polymath security token registry contract
 */
contract ISecurityTokenRegistry {

    bytes32 public protocolVersion = "0.0.1";
    mapping (bytes32 => address) public protocolVersionST;

    struct SecurityTokenData {
        string symbol;
        string tokenDetails;
    }

    mapping(address => SecurityTokenData) securityTokens;
    mapping(string => address) symbols;

    /**
     * @notice Creates a new Security Token and saves it to the registry
     * @param _name Name of the token
     * @param _symbol Ticker symbol of the security token
     * @param _tokenDetails off-chain details of the token
     */
    function generateSecurityToken(string _name, string _symbol, string _tokenDetails, bool _divisible) public;

    function setProtocolVersion(address _stVersionProxyAddress, bytes32 _version) public;

    /**
     * @notice Get security token address by ticker name
     * @param _symbol Symbol of the Scurity token
     * @return address _symbol
     */
    function getSecurityTokenAddress(string _symbol) public view returns (address);

     /**
     * @notice Get security token data by its address
     * @param _securityToken Address of the Scurity token
     * @return string, address, bytes32
     */
    function getSecurityTokenData(address _securityToken) public view returns (string, address, string);

    /**
    * @notice Check that Security Token is registered
    * @param _securityToken Address of the Scurity token
    * @return bool
    */
    function isSecurityToken(address _securityToken) public view returns (bool);
}

/**
 * @title Utility contract to allow owner to retreive any ERC20 sent to the contract
 */
contract ReclaimTokens is Ownable {

    /**
    * @notice Reclaim all ERC20Basic compatible tokens
    * @param _tokenContract The address of the token contract
    */
    function reclaimERC20(address _tokenContract) external onlyOwner {
        require(_tokenContract != address(0));
        ERC20Basic token = ERC20Basic(_tokenContract);
        uint256 balance = token.balanceOf(address(this));
        require(token.transfer(owner, balance));
    }
}

/**
 * @title Core functionality for registry upgradability
 */
contract Registry is IRegistry, Pausable, ReclaimTokens {

    /*
    Valid Address Keys
    tickerRegistry = getAddress("TickerRegistry")
    securityTokenRegistry = getAddress("SecurityTokenRegistry")
    moduleRegistry = getAddress("ModuleRegistry")
    polyToken = getAddress("PolyToken")
    */

    mapping (bytes32 => address) public storedAddresses;
    mapping (bytes32 => bool) public validAddressKeys;

    event LogChangeAddress(string _nameKey, address indexed _oldAddress, address indexed _newAddress);

    /**
     * @notice Get the contract address
     * @param _nameKey is the key for the contract address mapping
     * @return address
     */
    function getAddress(string _nameKey) view public returns(address) {
        require(validAddressKeys[keccak256(bytes(_nameKey))]);
        return storedAddresses[keccak256(bytes(_nameKey))];
    }

    /**
     * @notice change the contract address
     * @param _nameKey is the key for the contract address mapping
     * @param _newAddress is the new contract address
     */
    function changeAddress(string _nameKey, address _newAddress) public onlyOwner {
        address oldAddress;
        if (validAddressKeys[keccak256(bytes(_nameKey))]) {
            oldAddress = getAddress(_nameKey);
        } else {
            validAddressKeys[keccak256(bytes(_nameKey))] = true;
        }
        storedAddresses[keccak256(bytes(_nameKey))] = _newAddress;
        emit LogChangeAddress(_nameKey, oldAddress, _newAddress);
    }

    /**
     * @notice pause registration function
     */
    function unpause() public onlyOwner  {
        super._unpause();
    }

    /**
     * @notice unpause registration function
     */
    function pause() public onlyOwner {
        super._pause();
    }

}

/**
* @title Registry contract to store registered modules
* @notice Anyone can register modules, but only those "approved" by Polymath will be available for issuers to add
*/
contract ModuleRegistry is IModuleRegistry, Registry {

    // Mapping used to hold the type of module factory corresponds to the address of the Module factory contract
    mapping (address => uint8) public registry;
    // Mapping used to hold the reputation of the factory
    mapping (address => address[]) public reputation;
    // Mapping contain the list of addresses of Module factory for a particular type
    mapping (uint8 => address[]) public moduleList;
    // contains the list of verified modules
    mapping (address => bool) public verified;
    // Contains the list of the available tags corresponds to the module type
    mapping (uint8 => bytes32[]) public availableTags;

    // Emit when Module been used by the securityToken
    event LogModuleUsed(address indexed _moduleFactory, address indexed _securityToken);
    // Emit when the Module Factory get registered with the ModuleRegistry contract
    event LogModuleRegistered(address indexed _moduleFactory, address indexed _owner);
    // Emit when the module get verified by the Polymath team
    event LogModuleVerified(address indexed _moduleFactory, bool _verified);

    /**
    * @notice Called by a security token to notify the registry it is using a module
    * @param _moduleFactory is the address of the relevant module factory
    */
    function useModule(address _moduleFactory) external {
        //If caller is a registered security token, then register module usage
        if (ISecurityTokenRegistry(getAddress("SecurityTokenRegistry")).isSecurityToken(msg.sender)) {
            require(registry[_moduleFactory] != 0, "ModuleFactory type should not be 0");
            //To use a module, either it must be verified, or owned by the ST owner
            require(verified[_moduleFactory]||(IModuleFactory(_moduleFactory).owner() == ISecurityToken(msg.sender).owner()),
              "Module factory is not verified as well as not called by the owner");
            reputation[_moduleFactory].push(msg.sender);
            emit LogModuleUsed (_moduleFactory, msg.sender);
        }
    }

    /**
    * @notice Called by moduleFactory owner to register new modules for SecurityToken to use
    * @param _moduleFactory is the address of the module factory to be registered
    * @return bool
    */
    function registerModule(address _moduleFactory) external whenNotPaused returns(bool) {
        require(registry[_moduleFactory] == 0, "Module factory should not be pre-registered");
        IModuleFactory moduleFactory = IModuleFactory(_moduleFactory);
        require(moduleFactory.getType() != 0, "Factory type should not equal to 0");
        registry[_moduleFactory] = moduleFactory.getType();
        moduleList[moduleFactory.getType()].push(_moduleFactory);
        reputation[_moduleFactory] = new address[](0);
        emit LogModuleRegistered (_moduleFactory, moduleFactory.owner());
        return true;
    }

    /**
    * @notice Called by Polymath to verify modules for SecurityToken to use.
    * @notice A module can not be used by an ST unless first approved/verified by Polymath
    * @notice (The only exception to this is that the author of the module is the owner of the ST)
    * @param _moduleFactory is the address of the module factory to be registered
    * @return bool
    */
    function verifyModule(address _moduleFactory, bool _verified) external onlyOwner returns(bool) {
        //Must already have been registered
        require(registry[_moduleFactory] != 0, "Module factory should have been already registered");
        verified[_moduleFactory] = _verified;
        emit LogModuleVerified(_moduleFactory, _verified);
        return true;
    }

    /**
     * @notice Use to get all the tags releated to the functionality of the Module Factory.
     * @param _moduleType Type of module
     * @return bytes32 array
     */
    function getTagByModuleType(uint8 _moduleType) public view returns(bytes32[]) {
        return availableTags[_moduleType];
    }

    /**
     * @notice Add the tag for specified Module Factory
     * @param _moduleType Type of module.
     * @param _tag List of tags
     */
     function addTagByModuleType(uint8 _moduleType, bytes32[] _tag) public onlyOwner {
         for (uint8 i = 0; i < _tag.length; i++) {
             availableTags[_moduleType].push(_tag[i]);
         }
     }

    /**
     * @notice remove the tag for specified Module Factory
     * @param _moduleType Type of module.
     * @param _removedTags List of tags
     */
     function removeTagByModuleType(uint8 _moduleType, bytes32[] _removedTags) public onlyOwner {
         for (uint8 i = 0; i < availableTags[_moduleType].length; i++) {
            for (uint8 j = 0; j < _removedTags.length; j++) {
                if (availableTags[_moduleType][i] == _removedTags[j]) {
                    delete availableTags[_moduleType][i];
                }
            }
        }
     }

}

/**
 * @title Interface for the polymath ticker registry contract
 */
contract ITickerRegistry {
    /**
    * @notice Check the validity of the symbol
    * @param _symbol token symbol
    * @param _owner address of the owner
    * @param _tokenName Name of the token
    * @return bool
    */
    function checkValidity(string _symbol, address _owner, string _tokenName) public returns(bool);

    /**
    * @notice Returns the owner and timestamp for a given symbol
    * @param _symbol symbol
    */
    function getDetails(string _symbol) public view returns (address, uint256, string, bytes32, bool);

    /**
     * @notice Check the symbol is reserved or not
     * @param _symbol Symbol of the token
     * @return bool
     */
     function isReserved(string _symbol, address _owner, string _tokenName, bytes32 _swarmHash) public returns(bool);

}

contract ISTProxy {

    function deployToken(string _name, string _symbol, uint8 _decimals, string _tokenDetails, address _issuer, bool _divisible)
        public returns (address);
}

contract Util {

   /**
    * @dev changes a string to upper case
    * @param _base string to change
    */
    function upper(string _base) internal pure returns (string) {
        bytes memory _baseBytes = bytes(_base);
        for (uint i = 0; i < _baseBytes.length; i++) {
            bytes1 b1 = _baseBytes[i];
            if (b1 >= 0x61 && b1 <= 0x7A) {
                b1 = bytes1(uint8(b1)-32);
            }
            _baseBytes[i] = b1;
        }
        return string(_baseBytes);
    }

}

/**
 * @title Registry contract for issuers to reserve their security token symbols
 * @notice Allows issuers to reserve their token symbols ahead of actually generating their security token.
 * @dev SecurityTokenRegistry would reference this contract and ensure that a token symbol exists here and only its owner can deploy the token with that symbol.
 */
contract TickerRegistry is ITickerRegistry, Util, Registry {

    using SafeMath for uint256;
    // constant variable to check the validity to use the symbol
    // For now it's value is 15 days;
    uint256 public expiryLimit = 15 * 1 days;

    // Details of the symbol that get registered with the polymath platform
    struct SymbolDetails {
        address owner;
        uint256 timestamp;
        string tokenName;
        bytes32 swarmHash;
        bool status;
    }

    // Storage of symbols correspond to their details.
    mapping(string => SymbolDetails) registeredSymbols;

    // Emit after the symbol registration
    event LogRegisterTicker(address indexed _owner, string _symbol, string _name, bytes32 _swarmHash, uint256 indexed _timestamp);
    // Emit when the token symbol expiry get changed
    event LogChangeExpiryLimit(uint256 _oldExpiry, uint256 _newExpiry);

    // Registration fee in POLY base 18 decimals
    uint256 public registrationFee;
    // Emit when changePolyRegisterationFee is called
    event LogChangePolyRegisterationFee(uint256 _oldFee, uint256 _newFee);

    constructor (address _polyToken, uint256 _registrationFee) public {
        changeAddress("PolyToken", _polyToken);
        registrationFee = _registrationFee;
    }

    /**
     * @notice Register the token symbol for its particular owner
     * @notice Once the token symbol is registered to its owner then no other issuer can claim
     * @notice its ownership. If the symbol expires and its issuer hasn't used it, then someone else can take it.
     * @param _symbol token symbol
     * @param _tokenName Name of the token
     * @param _owner Address of the owner of the token
     * @param _swarmHash Off-chain details of the issuer and token
     */
    function registerTicker(address _owner, string _symbol, string _tokenName, bytes32 _swarmHash) public whenNotPaused {
        require(bytes(_symbol).length > 0 && bytes(_symbol).length <= 10, "Ticker length should always between 0 & 10");
        if(registrationFee > 0)
            require(ERC20(getAddress("PolyToken")).transferFrom(msg.sender, this, registrationFee), "Failed transferFrom because of sufficent Allowance is not provided");
        string memory symbol = upper(_symbol);
        require(expiryCheck(symbol), "Ticker is already reserved");
        registeredSymbols[symbol] = SymbolDetails(_owner, now, _tokenName, _swarmHash, false);
        emit LogRegisterTicker (_owner, symbol, _tokenName, _swarmHash, now);
    }

    /**
     * @notice Change the expiry time for the token symbol
     * @param _newExpiry new time period for token symbol expiry
     */
    function changeExpiryLimit(uint256 _newExpiry) public onlyOwner {
        require(_newExpiry >= 1 days, "Expiry should greater than or equal to 1 day");
        uint256 _oldExpiry = expiryLimit;
        expiryLimit = _newExpiry;
        emit LogChangeExpiryLimit(_oldExpiry, _newExpiry);
    }

    /**
     * @notice Check the validity of the symbol
     * @param _symbol token symbol
     * @param _owner address of the owner
     * @param _tokenName Name of the token
     * @return bool
     */
    function checkValidity(string _symbol, address _owner, string _tokenName) public returns(bool) {
        string memory symbol = upper(_symbol);
        require(msg.sender == getAddress("SecurityTokenRegistry"), "msg.sender should be SecurityTokenRegistry contract");
        require(registeredSymbols[symbol].status != true, "Symbol status should not equal to true");
        require(registeredSymbols[symbol].owner == _owner, "Owner of the symbol should matched with the requested issuer address");
        require(registeredSymbols[symbol].timestamp.add(expiryLimit) >= now, "Ticker should not be expired");
        registeredSymbols[symbol].tokenName = _tokenName;
        registeredSymbols[symbol].status = true;
        return true;
    }

    /**
     * @notice Check the symbol is reserved or not
     * @param _symbol Symbol of the token
     * @param _owner Owner of the token
     * @param _tokenName Name of the token
     * @param _swarmHash off-chain hash
     * @return bool
     */
     function isReserved(string _symbol, address _owner, string _tokenName, bytes32 _swarmHash) public returns(bool) {
        string memory symbol = upper(_symbol);
        require(msg.sender == getAddress("SecurityTokenRegistry"), "msg.sender should be SecurityTokenRegistry contract");
        if (registeredSymbols[symbol].owner == _owner && !expiryCheck(_symbol)) {
            registeredSymbols[symbol].status = true;
            return false;
        }
        else if (registeredSymbols[symbol].owner == address(0) || expiryCheck(symbol)) {
            registeredSymbols[symbol] = SymbolDetails(_owner, now, _tokenName, _swarmHash, true);
            emit LogRegisterTicker (_owner, symbol, _tokenName, _swarmHash, now);
            return false;
        } else
            return true;
     }

    /**
     * @notice Returns the owner and timestamp for a given symbol
     * @param _symbol symbol
     * @return address
     * @return uint256
     * @return string
     * @return bytes32
     * @return bool
     */
    function getDetails(string _symbol) public view returns (address, uint256, string, bytes32, bool) {
        string memory symbol = upper(_symbol);
        if (registeredSymbols[symbol].status == true||registeredSymbols[symbol].timestamp.add(expiryLimit) > now) {
            return
            (
                registeredSymbols[symbol].owner,
                registeredSymbols[symbol].timestamp,
                registeredSymbols[symbol].tokenName,
                registeredSymbols[symbol].swarmHash,
                registeredSymbols[symbol].status
            );
        }else
            return (address(0), uint256(0), "", bytes32(0), false);
    }

    /**
     * @notice To re-initialize the token symbol details if symbol validity expires
     * @param _symbol token symbol
     * @return bool
     */
    function expiryCheck(string _symbol) internal returns(bool) {
        if (registeredSymbols[_symbol].owner != address(0)) {
            if (now > registeredSymbols[_symbol].timestamp.add(expiryLimit) && registeredSymbols[_symbol].status != true) {
                registeredSymbols[_symbol] = SymbolDetails(address(0), uint256(0), "", bytes32(0), false);
                return true;
            }else
                return false;
        }
        return true;
    }

    /**
     * @notice set the ticker registration fee in POLY tokens
     * @param _registrationFee registration fee in POLY tokens (base 18 decimals)
     */
    function changePolyRegisterationFee(uint256 _registrationFee) public onlyOwner {
        require(registrationFee != _registrationFee);
        emit LogChangePolyRegisterationFee(registrationFee, _registrationFee);
        registrationFee = _registrationFee;
    }
}

/**
 * @title Registry contract for issuers to register their security tokens
 */
contract SecurityTokenRegistry is ISecurityTokenRegistry, Util, Registry {

    // Registration fee in POLY base 18 decimals
    uint256 public registrationFee;
    // Emit when changePolyRegisterationFee is called
    event LogChangePolyRegisterationFee(uint256 _oldFee, uint256 _newFee);

    // Emit at the time of launching of new security token
    event LogNewSecurityToken(string _ticker, address indexed _securityTokenAddress, address _owner);
    event LogAddCustomSecurityToken(string _name, string _symbol, address _securityToken, uint256 _addedAt);

    constructor (
        address _polyToken,
        address _moduleRegistry,
        address _tickerRegistry,
        address _stVersionProxy,
        uint256 _registrationFee
    )
    public
    {
        changeAddress("PolyToken", _polyToken);
        changeAddress("ModuleRegistry", _moduleRegistry);
        changeAddress("TickerRegistry", _tickerRegistry);
        registrationFee = _registrationFee;

        // By default, the STR version is set to 0.0.1
        setProtocolVersion(_stVersionProxy, "0.0.1");
    }

    /**
     * @notice Creates a new Security Token and saves it to the registry
     * @param _name Name of the token
     * @param _symbol Ticker symbol of the security token
     * @param _tokenDetails off-chain details of the token
     * @param _divisible Set to true if token is divisible
     */
    function generateSecurityToken(string _name, string _symbol, string _tokenDetails, bool _divisible) public whenNotPaused {
        require(bytes(_name).length > 0 && bytes(_symbol).length > 0, "Name and Symbol string length should be greater than 0");
        require(ITickerRegistry(getAddress("TickerRegistry")).checkValidity(_symbol, msg.sender, _name), "Trying to use non-valid symbol");
        if(registrationFee > 0)
            require(ERC20(getAddress("PolyToken")).transferFrom(msg.sender, this, registrationFee), "Failed transferFrom because of sufficent Allowance is not provided");
        string memory symbol = upper(_symbol);
        address newSecurityTokenAddress = ISTProxy(protocolVersionST[protocolVersion]).deployToken(
            _name,
            symbol,
            18,
            _tokenDetails,
            msg.sender,
            _divisible
        );

        securityTokens[newSecurityTokenAddress] = SecurityTokenData(symbol, _tokenDetails);
        symbols[symbol] = newSecurityTokenAddress;
        emit LogNewSecurityToken(symbol, newSecurityTokenAddress, msg.sender);
    }

    /**
     * @notice Add a new custom (Token should follow the ISecurityToken interface) Security Token and saves it to the registry
     * @param _name Name of the token
     * @param _symbol Ticker symbol of the security token
     * @param _owner Owner of the token
     * @param _securityToken Address of the securityToken
     * @param _tokenDetails off-chain details of the token
     * @param _swarmHash off-chain details about the issuer company
     */
    function addCustomSecurityToken(string _name, string _symbol, address _owner, address _securityToken, string _tokenDetails, bytes32 _swarmHash) public onlyOwner whenNotPaused {
        require(bytes(_name).length > 0 && bytes(_symbol).length > 0, "Name and Symbol string length should be greater than 0");
        require(_securityToken != address(0) && symbols[_symbol] == address(0), "Symbol is already at the polymath network or entered security token address is 0x");
        require(_owner != address(0));
        require(!(ITickerRegistry(getAddress("TickerRegistry")).isReserved(_symbol, _owner, _name, _swarmHash)), "Trying to use non-valid symbol");
        symbols[_symbol] = _securityToken;
        securityTokens[_securityToken] = SecurityTokenData(_symbol, _tokenDetails);
        emit LogAddCustomSecurityToken(_name, _symbol, _securityToken, now);
    }

    /**
    * @notice Changes the protocol version and the SecurityToken contract
    * @notice Used only by Polymath to upgrade the SecurityToken contract and add more functionalities to future versions
    * @notice Changing versions does not affect existing tokens.
    */
    function setProtocolVersion(address _stVersionProxyAddress, bytes32 _version) public onlyOwner {
        protocolVersion = _version;
        protocolVersionST[_version] = _stVersionProxyAddress;
    }

    //////////////////////////////
    ///////// Get Functions
    //////////////////////////////
    /**
     * @notice Get security token address by ticker name
     * @param _symbol Symbol of the Scurity token
     * @return address
     */
    function getSecurityTokenAddress(string _symbol) public view returns (address) {
        string memory __symbol = upper(_symbol);
        return symbols[__symbol];
    }

     /**
     * @notice Get security token data by its address
     * @param _securityToken Address of the Scurity token
     * @return string
     * @return address
     * @return string
     */
    function getSecurityTokenData(address _securityToken) public view returns (string, address, string) {
        return (
            securityTokens[_securityToken].symbol,
            ISecurityToken(_securityToken).owner(),
            securityTokens[_securityToken].tokenDetails
        );
    }

    /**
    * @notice Check that Security Token is registered
    * @param _securityToken Address of the Scurity token
    * @return bool
    */
    function isSecurityToken(address _securityToken) public view returns (bool) {
        return (keccak256(bytes(securityTokens[_securityToken].symbol)) != keccak256(""));
    }

    /**
     * @notice set the ticker registration fee in POLY tokens
     * @param _registrationFee registration fee in POLY tokens (base 18 decimals)
     */
    function changePolyRegisterationFee(uint256 _registrationFee) public onlyOwner {
        require(registrationFee != _registrationFee);
        emit LogChangePolyRegisterationFee(registrationFee, _registrationFee);
        registrationFee = _registrationFee;
    }

}

contract PolyToken is MintableToken {

    constructor () public {

    }

}

/**
 * @title Interface for the token burner contract
 */
interface ITokenBurner {

    function burn(address _burner, uint256  _value ) external returns(bool);

}

contract TokenBurner is ITokenBurner {

    address public securityToken;

    constructor (address _securityToken) public {
        securityToken = _securityToken;
    }

    function burn(address /* _burner */, uint256 /* _value */) public view returns(bool) {
        require(msg.sender == securityToken);
        // Add the schematics for the burner( token holder) that backing the burning of the securities
        return true;
    }

}

/**
 * @title Transfer Manager module for core transfer validation functionality
 */
contract GeneralTransferManager is ITransferManager {

    using SafeMath for uint256;

    //Address from which issuances come
    address public issuanceAddress = address(0);

    //Address which can sign whitelist changes
    address public signingAddress = address(0);

    bytes32 public constant WHITELIST = "WHITELIST";
    bytes32 public constant FLAGS = "FLAGS";

    //from and to timestamps that an investor can send / receive tokens respectively
    struct TimeRestriction {
        uint256 fromTime;
        uint256 toTime;
        uint256 expiryTime;
        bool canBuyFromSTO;
    }

    // An address can only send / receive tokens once their corresponding uint256 > block.number
    // (unless allowAllTransfers == true or allowAllWhitelistTransfers == true)
    mapping (address => TimeRestriction) public whitelist;

    //If true, there are no transfer restrictions, for any addresses
    bool public allowAllTransfers = false;
    //If true, time lock is ignored for transfers (address must still be on whitelist)
    bool public allowAllWhitelistTransfers = false;
    //If true, time lock is ignored for issuances (address must still be on whitelist)
    bool public allowAllWhitelistIssuances = true;
    //If true, time lock is ignored for burn transactions
    bool public allowAllBurnTransfers = false;

    // Emit when Issuance address get changed
    event LogChangeIssuanceAddress(address _issuanceAddress);
    // Emit when there is change in the flag variable called allowAllTransfers
    event LogAllowAllTransfers(bool _allowAllTransfers);
    // Emit when there is change in the flag variable called allowAllWhitelistTransfers
    event LogAllowAllWhitelistTransfers(bool _allowAllWhitelistTransfers);
    // Emit when there is change in the flag variable called allowAllWhitelistIssuances
    event LogAllowAllWhitelistIssuances(bool _allowAllWhitelistIssuances);
    // Emit when there is change in the flag variable called allowAllBurnTransfers
    event LogAllowAllBurnTransfers(bool _allowAllBurnTransfers);
    // Emit when there is change in the flag variable called signingAddress
    event LogChangeSigningAddress(address _signingAddress);
    // Emit when investor details get modified related to their whitelisting
    event LogModifyWhitelist(
        address _investor,
        uint256 _dateAdded,
        address _addedBy,
        uint256 _fromTime,
        uint256 _toTime,
        uint256 _expiryTime,
        bool _canBuyFromSTO
    );

    /**
     * @notice Constructor
     * @param _securityToken Address of the security token
     * @param _polyAddress Address of the polytoken
     */
    constructor (address _securityToken, address _polyAddress)
    public
    IModule(_securityToken, _polyAddress)
    {
    }

    /**
     * @notice This function returns the signature of configure function
     */
    function getInitFunction() public returns(bytes4) {
        return bytes4(0);
    }

    /**
     * @notice Used to change the Issuance Address
     * @param _issuanceAddress new address for the issuance
     */
    function changeIssuanceAddress(address _issuanceAddress) public withPerm(FLAGS) {
        issuanceAddress = _issuanceAddress;
        emit LogChangeIssuanceAddress(_issuanceAddress);
    }

    /**
     * @notice Used to change the Sigining Address
     * @param _signingAddress new address for the signing
     */
    function changeSigningAddress(address _signingAddress) public withPerm(FLAGS) {
        signingAddress = _signingAddress;
        emit LogChangeSigningAddress(_signingAddress);
    }

    /**
     * @notice Used to change the flag
            true - It refers there are no transfer restrictions, for any addresses
            false - It refers transfers are restricted for all addresses.
     * @param _allowAllTransfers flag value
     */
    function changeAllowAllTransfers(bool _allowAllTransfers) public withPerm(FLAGS) {
        allowAllTransfers = _allowAllTransfers;
        emit LogAllowAllTransfers(_allowAllTransfers);
    }

    /**
     * @notice Used to change the flag
            true - It refers that time lock is ignored for transfers (address must still be on whitelist)
            false - It refers transfers are restricted for all addresses.
     * @param _allowAllWhitelistTransfers flag value
     */
    function changeAllowAllWhitelistTransfers(bool _allowAllWhitelistTransfers) public withPerm(FLAGS) {
        allowAllWhitelistTransfers = _allowAllWhitelistTransfers;
        emit LogAllowAllWhitelistTransfers(_allowAllWhitelistTransfers);
    }

    /**
     * @notice Used to change the flag
            true - It refers that time lock is ignored for issuances (address must still be on whitelist)
            false - It refers transfers are restricted for all addresses.
     * @param _allowAllWhitelistIssuances flag value
     */
    function changeAllowAllWhitelistIssuances(bool _allowAllWhitelistIssuances) public withPerm(FLAGS) {
        allowAllWhitelistIssuances = _allowAllWhitelistIssuances;
        emit LogAllowAllWhitelistIssuances(_allowAllWhitelistIssuances);
    }

    /**
     * @notice Used to change the flag
            true - It allow to burn the tokens
            false - It deactivate the burning mechanism.
     * @param _allowAllBurnTransfers flag value
     */
    function changeAllowAllBurnTransfers(bool _allowAllBurnTransfers) public withPerm(FLAGS) {
        allowAllBurnTransfers = _allowAllBurnTransfers;
        emit LogAllowAllBurnTransfers(_allowAllBurnTransfers);
    }

    /**
    * @notice default implementation of verifyTransfer used by SecurityToken
    * If the transfer request comes from the STO, it only checks that the investor is in the whitelist
    * If the transfer request comes from a token holder, it checks that:
    * a) Both are on the whitelist
    * b) Seller's sale lockup period is over
    * c) Buyer's purchase lockup is over
    */
    function verifyTransfer(address _from, address _to, uint256 /*_amount*/, bool /* _isTransfer */) public returns(Result) {
        if (!paused) {
            if (allowAllTransfers) {
                //All transfers allowed, regardless of whitelist
                return Result.VALID;
            }
            if (allowAllBurnTransfers && (_to == address(0))) {
                return Result.VALID;
            }
            if (allowAllWhitelistTransfers) {
                //Anyone on the whitelist can transfer, regardless of block number
                return (onWhitelist(_to) && onWhitelist(_from)) ? Result.VALID : Result.NA;
            }
            if (allowAllWhitelistIssuances && _from == issuanceAddress) {
                if (!whitelist[_to].canBuyFromSTO && isSTOAttached()) {
                    return Result.NA;
                }
                return onWhitelist(_to) ? Result.VALID : Result.NA;
            }
            //Anyone on the whitelist can transfer provided the blocknumber is large enough
            return ((onWhitelist(_from) && whitelist[_from].fromTime <= now) &&
                (onWhitelist(_to) && whitelist[_to].toTime <= now)) ? Result.VALID : Result.NA;
        }
        return Result.NA;
    }

    /**
    * @notice adds or removes addresses from the whitelist.
    * @param _investor is the address to whitelist
    * @param _fromTime is the moment when the sale lockup period ends and the investor can freely sell his tokens
    * @param _toTime is the moment when the purchase lockup period ends and the investor can freely purchase tokens from others
    * @param _expiryTime is the moment till investors KYC will be validated. After that investor need to do re-KYC
    * @param _canBuyFromSTO is used to know whether the investor is restricted investor or not.
    */
    function modifyWhitelist(address _investor, uint256 _fromTime, uint256 _toTime, uint256 _expiryTime, bool _canBuyFromSTO) public withPerm(WHITELIST) {
        //Passing a _time == 0 into this function, is equivalent to removing the _investor from the whitelist
        whitelist[_investor] = TimeRestriction(_fromTime, _toTime, _expiryTime, _canBuyFromSTO);
        emit LogModifyWhitelist(_investor, now, msg.sender, _fromTime, _toTime, _expiryTime, _canBuyFromSTO);
    }

    /**
    * @notice adds or removes addresses from the whitelist.
    * @param _investors List of the addresses to whitelist
    * @param _fromTimes An array of the moment when the sale lockup period ends and the investor can freely sell his tokens
    * @param _toTimes An array of the moment when the purchase lockup period ends and the investor can freely purchase tokens from others
    * @param _expiryTimes An array of the moment till investors KYC will be validated. After that investor need to do re-KYC
    * @param _canBuyFromSTO An array of boolean values
    */
    function modifyWhitelistMulti(
        address[] _investors,
        uint256[] _fromTimes,
        uint256[] _toTimes,
        uint256[] _expiryTimes,
        bool[] _canBuyFromSTO
    ) public withPerm(WHITELIST) {
        require(_investors.length == _fromTimes.length, "Mismatched input lengths");
        require(_fromTimes.length == _toTimes.length, "Mismatched input lengths");
        require(_toTimes.length == _expiryTimes.length, "Mismatched input lengths");
        require(_canBuyFromSTO.length == _toTimes.length, "Mismatched input length");
        for (uint256 i = 0; i < _investors.length; i++) {
            modifyWhitelist(_investors[i], _fromTimes[i], _toTimes[i], _expiryTimes[i], _canBuyFromSTO[i]);
        }
    }

    /**
    * @notice adds or removes addresses from the whitelist - can be called by anyone with a valid signature
    * @param _investor is the address to whitelist
    * @param _fromTime is the moment when the sale lockup period ends and the investor can freely sell his tokens
    * @param _toTime is the moment when the purchase lockup period ends and the investor can freely purchase tokens from others
    * @param _expiryTime is the moment till investors KYC will be validated. After that investor need to do re-KYC
    * @param _canBuyFromSTO is used to know whether the investor is restricted investor or not.
    * @param _validFrom is the time that this signature is valid from
    * @param _validTo is the time that this signature is valid until
    * @param _v issuer signature
    * @param _r issuer signature
    * @param _s issuer signature
    */
    function modifyWhitelistSigned(
        address _investor,
        uint256 _fromTime,
        uint256 _toTime,
        uint256 _expiryTime,
        bool _canBuyFromSTO,
        uint256 _validFrom,
        uint256 _validTo,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) public {
        require(_validFrom <= now, "ValidFrom is too early");
        require(_validTo >= now, "ValidTo is too late");
        bytes32 hash = keccak256(abi.encodePacked(this, _investor, _fromTime, _toTime, _expiryTime, _canBuyFromSTO, _validFrom, _validTo));
        checkSig(hash, _v, _r, _s);
        //Passing a _time == 0 into this function, is equivalent to removing the _investor from the whitelist
        whitelist[_investor] = TimeRestriction(_fromTime, _toTime, _expiryTime, _canBuyFromSTO);
        emit LogModifyWhitelist(_investor, now, msg.sender, _fromTime, _toTime, _expiryTime, _canBuyFromSTO);
    }

    /**
     * @notice used to verify the signature
     */
    function checkSig(bytes32 _hash, uint8 _v, bytes32 _r, bytes32 _s) internal view {
        //Check that the signature is valid
        //sig should be signing - _investor, _fromTime, _toTime & _expiryTime and be signed by the issuer address
        address signer = ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _hash)), _v, _r, _s);
        require(signer == ISecurityToken(securityToken).owner() || signer == signingAddress, "Incorrect signer");
    }

    /**
     * @notice Return the permissions flag that are associated with general trnasfer manager
     */
    function getPermissions() public view returns(bytes32[]) {
        bytes32[] memory allPermissions = new bytes32[](2);
        allPermissions[0] = WHITELIST;
        allPermissions[1] = FLAGS;
        return allPermissions;
    }

    /**
     * @notice Internal function used to check whether the investor is in the whitelist or not
            & also checks whether the KYC of investor get expired or not
     * @param _investor Address of the investor
     */
    function onWhitelist(address _investor) internal view returns(bool) {
        return (((whitelist[_investor].fromTime != 0) || (whitelist[_investor].toTime != 0)) &&
            (whitelist[_investor].expiryTime >= now));
    }

    /**
     * @notice Internal function use to know whether the STO is attached or not
     */
    function isSTOAttached() internal view returns(bool) {
        address _sto;
        bytes32 _modName;
        (_modName, _sto) = ISecurityToken(securityToken).getModule(3, 0);
        if (_sto == address(0))
            return false;
        return true;
    }

}

/**
 * @title Factory for deploying GeneralTransferManager module
 */
contract GeneralTransferManagerFactory is IModuleFactory {

    /**
     * @notice Constructor
     * @param _polyAddress Address of the polytoken
     */
    constructor (address _polyAddress, uint256 _setupCost, uint256 _usageCost, uint256 _subscriptionCost) public
      IModuleFactory(_polyAddress, _setupCost, _usageCost, _subscriptionCost)
    {

    }


     /**
     * @notice used to launch the Module with the help of factory
     * @return address Contract address of the Module
     */
    function deploy(bytes /* _data */) external returns(address) {
        if (setupCost > 0)
            require(polyToken.transferFrom(msg.sender, owner, setupCost), "Failed transferFrom because of sufficent Allowance is not provided");
        address generalTransferManager = new GeneralTransferManager(msg.sender, address(polyToken));
        emit LogGenerateModuleFromFactory(address(generalTransferManager), getName(), address(this), msg.sender, now);
        return address(generalTransferManager);
    }


    /**
     * @notice Type of the Module factory
     */
    function getType() public view returns(uint8) {
        return 2;
    }

    /**
     * @notice Get the name of the Module
     */
    function getName() public view returns(bytes32) {
        return "GeneralTransferManager";
    }

    /**
     * @notice Get the description of the Module
     */
    function getDescription() public view returns(string) {
        return "Manage transfers using a time based whitelist";
    }

    /**
     * @notice Get the title of the Module
     */
    function getTitle() public view returns(string) {
        return "General Transfer Manager";
    }

    /**
     * @notice Get the Instructions that helped to used the module
     */
    function getInstructions() public view returns(string) {
        return "Allows an issuer to maintain a time based whitelist of authorised token holders.Addresses are added via modifyWhitelist, and take a fromTime (the time from which they can send tokens) and a toTime (the time from which they can receive tokens). There are additional flags, allowAllWhitelistIssuances, allowAllWhitelistTransfers & allowAllTransfers which allow you to set corresponding contract level behaviour. Init function takes no parameters.";
    }

    /**
     * @notice Get the tags related to the module factory
     */
    function getTags() public view returns(bytes32[]) {
         bytes32[] memory availableTags = new bytes32[](2);
        availableTags[0] = "General";
        availableTags[1] = "Transfer Restriction";
        return availableTags;
    }


}

/**
 * @title Permission Manager module for core permissioning functionality
 */
contract GeneralPermissionManager is IPermissionManager {

    // Mapping used to hold the permissions on the modules provided to delegate
    mapping (address => mapping (address => mapping (bytes32 => bool))) public perms;
    // Mapping hold the delagate details
    mapping (address => bytes32) public delegateDetails;
    // Permission flag
    bytes32 public constant CHANGE_PERMISSION = "CHANGE_PERMISSION";

    /// Event emitted after any permission get changed for the delegate
    event LogChangePermission(address _delegate, address _module, bytes32 _perm, bool _valid, uint256 _timestamp);
    /// Use to notify when delegate is added in permission manager contract
    event LogAddPermission(address _delegate, bytes32 _details, uint256 _timestamp);

    /// @notice constructor
    constructor (address _securityToken, address _polyAddress) public
    IModule(_securityToken, _polyAddress)
    {
    }

    /**
    * @notice Init function i.e generalise function to maintain the structure of the module contract
    * @return bytes4
    */
    function getInitFunction() public returns(bytes4) {
        return bytes4(0);
    }

    /**
    * @notice use to check the permission on delegate corresponds to module contract address
    * @param _delegate Ethereum address of the delegate
    * @param _module Ethereum contract address of the module
    * @param _perm Permission flag
    * @return bool
    */
    function checkPermission(address _delegate, address _module, bytes32 _perm) public view returns(bool) {
        if (delegateDetails[_delegate] != bytes32(0)) {
            return perms[_module][_delegate][_perm];
        }else
            return false;
    }

    /**
    * @notice use to add the details of the delegate
    * @param _delegate Ethereum address of the delegate
    * @param _details Details about the delegate i.e `Belongs to financial firm`
    */
    function addPermission(address _delegate, bytes32 _details) public withPerm(CHANGE_PERMISSION) {
        delegateDetails[_delegate] = _details;
        emit LogAddPermission(_delegate, _details, now);
    }

  /**
    * @notice Use to provide/change the permission to the delegate corresponds to the module contract
    * @param _delegate Ethereum address of the delegate
    * @param _module Ethereum contract address of the module
    * @param _perm Permission flag
    * @param _valid Bool flag use to switch on/off the permission
    * @return bool
    */
    function changePermission(
        address _delegate,
        address _module,
        bytes32 _perm,
        bool _valid
    )
    public
    withPerm(CHANGE_PERMISSION)
    returns(bool)
    {
        require(delegateDetails[_delegate] != bytes32(0), "Delegate details not set");
        perms[_module][_delegate][_perm] = _valid;
        emit LogChangePermission(_delegate, _module, _perm, _valid, now);
        return true;
    }

    /**
    * @notice Use to get the details of the delegate
    * @param _delegate Ethereum address of the delegate
    * @return Details of the delegate
    */
    function getDelegateDetails(address _delegate) public view returns(bytes32) {
        return delegateDetails[_delegate];
    }

    /**
    * @notice Use to get the Permission flag related the `this` contract
    * @return Array of permission flags
    */
    function getPermissions() public view returns(bytes32[]) {
        bytes32[] memory allPermissions = new bytes32[](1);
        allPermissions[0] = CHANGE_PERMISSION;
        return allPermissions;
    }

}

/**
 * @title Factory for deploying GeneralPermissionManager module
 */
contract GeneralPermissionManagerFactory is IModuleFactory {

    /**
     * @notice Constructor
     * @param _polyAddress Address of the polytoken
     */
    constructor (address _polyAddress, uint256 _setupCost, uint256 _usageCost, uint256 _subscriptionCost) public
      IModuleFactory(_polyAddress, _setupCost, _usageCost, _subscriptionCost)
    {

    }

    /**
     * @notice used to launch the Module with the help of factory
     * @return address Contract address of the Module
     */
    function deploy(bytes /* _data */) external returns(address) {
        if(setupCost > 0)
            require(polyToken.transferFrom(msg.sender, owner, setupCost), "Failed transferFrom because of sufficent Allowance is not provided");
        address permissionManager = new GeneralPermissionManager(msg.sender, address(polyToken));
        emit LogGenerateModuleFromFactory(address(permissionManager), getName(), address(this), msg.sender, now);
        return address(permissionManager);
    }

    /**
     * @notice Type of the Module factory
     */
    function getType() public view returns(uint8) {
        return 1;
    }

    /**
     * @notice Get the name of the Module
     */
    function getName() public view returns(bytes32) {
        return "GeneralPermissionManager";
    }

    /**
     * @notice Get the description of the Module
     */
    function getDescription() public view returns(string) {
        return "Manage permissions within the Security Token and attached modules";
    }

    /**
     * @notice Get the title of the Module
     */
    function getTitle() public  view returns(string) {
        return "General Permission Manager";
    }

    /**
     * @notice Get the Instructions that helped to used the module
     */
    function getInstructions() public view returns(string) {
        return "Add and remove permissions for the SecurityToken and associated modules. Permission types should be encoded as bytes32 values, and attached using the withPerm modifier to relevant functions.No initFunction required.";
    }

    /**
     * @notice Get the tags related to the module factory
     */
    function getTags() public view returns(bytes32[]) {
        bytes32[] memory availableTags = new bytes32[](1);
        return availableTags;
    }
}

/**
* @title Security Token contract
* @notice SecurityToken is an ERC20 token with added capabilities:
* @notice - Implements the ST-20 Interface
* @notice - Transfers are restricted
* @notice - Modules can be attached to it to control its behaviour
* @notice - ST should not be deployed directly, but rather the SecurityTokenRegistry should be used
*/
contract SecurityToken is ISecurityToken {
    using SafeMath for uint256;

    bytes32 public securityTokenVersion = "0.0.1";

    // Reference to token burner contract
    ITokenBurner public tokenBurner;

    // Use to halt all the transactions
    bool public freeze = false;

    // Reference to STR contract
    address public securityTokenRegistry;

    struct ModuleData {
        bytes32 name;
        address moduleAddress;
    }

    // Structures to maintain checkpoints of balances for governance / dividends
    struct Checkpoint {
        uint256 checkpointId;
        uint256 value;
    }

    mapping (address => Checkpoint[]) public checkpointBalances;
    Checkpoint[] public checkpointTotalSupply;

    bool public finishedIssuerMinting = false;
    bool public finishedSTOMinting = false;

    mapping (bytes4 => bool) transferFunctions;

    // Module list should be order agnostic!
    mapping (uint8 => ModuleData[]) public modules;

    uint8 public constant MAX_MODULES = 20;

    mapping (address => bool) public investorListed;

    // Emit at the time when module get added
    event LogModuleAdded(
        uint8 indexed _type,
        bytes32 _name,
        address _moduleFactory,
        address _module,
        uint256 _moduleCost,
        uint256 _budget,
        uint256 _timestamp
    );

    // Emit when the token details get updated
    event LogUpdateTokenDetails(string _oldDetails, string _newDetails);
    // Emit when the granularity get changed
    event LogGranularityChanged(uint256 _oldGranularity, uint256 _newGranularity);
    // Emit when Module get removed from the securityToken
    event LogModuleRemoved(uint8 indexed _type, address _module, uint256 _timestamp);
    // Emit when the budget allocated to a module is changed
    event LogModuleBudgetChanged(uint8 indexed _moduleType, address _module, uint256 _budget);
    // Emit when all the transfers get freeze
    event LogFreezeTransfers(bool _freeze, uint256 _timestamp);
    // Emit when new checkpoint created
    event LogCheckpointCreated(uint256 indexed _checkpointId, uint256 _timestamp);
    // Emit when the minting get finished for the Issuer
    event LogFinishMintingIssuer(uint256 _timestamp);
    // Emit when the minting get finished for the STOs
    event LogFinishMintingSTO(uint256 _timestamp);
    // Change the STR address in the event of a upgrade
    event LogChangeSTRAddress(address indexed _oldAddress, address indexed _newAddress);

    // If _fallback is true, then for STO module type we only allow the module if it is set, if it is not set we only allow the owner 
    // for other _moduleType we allow both issuer and module. 
    modifier onlyModule(uint8 _moduleType, bool _fallback) {
      //Loop over all modules of type _moduleType
        bool isModuleType = false;
        for (uint8 i = 0; i < modules[_moduleType].length; i++) {
            isModuleType = isModuleType || (modules[_moduleType][i].moduleAddress == msg.sender);
        }
        if (_fallback && !isModuleType) {
            if (_moduleType == STO_KEY)
                require(modules[_moduleType].length == 0 && msg.sender == owner, "Sender is not owner or STO module is attached");
            else
                require(msg.sender == owner, "Sender is not owner");
        } else {
            require(isModuleType, "Sender is not correct module type");
        }
        _;
    }

    modifier checkGranularity(uint256 _amount) {
        require(_amount.div(granularity).mul(granularity) == _amount, "Unable to modify token balances at this granularity");
        _;
    }

    // Checks whether the minting is allowed or not, check for the owner if owner is no the msg.sender then check
    // for the finishedSTOMinting flag because only STOs and owner are allowed for minting
    modifier isMintingAllowed() {
        if (msg.sender == owner) {
            require(!finishedIssuerMinting, "Minting is finished for Issuer");
        } else {
            require(!finishedSTOMinting, "Minting is finished for STOs");
        }
        _;
    }

    /**
     * @notice Constructor
     * @param _name Name of the SecurityToken
     * @param _symbol Symbol of the Token
     * @param _decimals Decimals for the securityToken
     * @param _granularity granular level of the token
     * @param _tokenDetails Details of the token that are stored off-chain (IPFS hash)
     * @param _securityTokenRegistry Contract address of the security token registry
     */
    constructor (
        string _name,
        string _symbol,
        uint8 _decimals,
        uint256 _granularity,
        string _tokenDetails,
        address _securityTokenRegistry
    )
    public
    DetailedERC20(_name, _symbol, _decimals)
    {
        //When it is created, the owner is the STR
        securityTokenRegistry = _securityTokenRegistry;
        tokenDetails = _tokenDetails;
        granularity = _granularity;
        transferFunctions[bytes4(keccak256("transfer(address,uint256)"))] = true;
        transferFunctions[bytes4(keccak256("transferFrom(address,address,uint256)"))] = true;
        transferFunctions[bytes4(keccak256("mint(address,uint256)"))] = true;
        transferFunctions[bytes4(keccak256("burn(uint256)"))] = true;
    }

    /**
     * @notice Function used to attach the module in security token
     * @param _moduleFactory Contract address of the module factory that needs to be attached
     * @param _data Data used for the intialization of the module factory variables
     * @param _maxCost Maximum cost of the Module factory
     * @param _budget Budget of the Module factory
     */
    function addModule(
        address _moduleFactory,
        bytes _data,
        uint256 _maxCost,
        uint256 _budget
    ) external onlyOwner {
        _addModule(_moduleFactory, _data, _maxCost, _budget);
    }

    /**
    * @notice _addModule handles the attachment (or replacement) of modules for the ST
    * @dev  E.G.: On deployment (through the STR) ST gets a TransferManager module attached to it
    * @dev to control restrictions on transfers.
    * @dev You are allowed to add a new moduleType if:
    * @dev - there is no existing module of that type yet added
    * @dev - the last member of the module list is replacable
    * @param _moduleFactory is the address of the module factory to be added
    * @param _data is data packed into bytes used to further configure the module (See STO usage)
    * @param _maxCost max amount of POLY willing to pay to module. (WIP)
    */
    function _addModule(address _moduleFactory, bytes _data, uint256 _maxCost, uint256 _budget) internal {
        //Check that module exists in registry - will throw otherwise
        IModuleRegistry(IRegistry(securityTokenRegistry).getAddress("ModuleRegistry")).useModule(_moduleFactory);
        IModuleFactory moduleFactory = IModuleFactory(_moduleFactory);
        require(modules[moduleFactory.getType()].length < MAX_MODULES, "Limit of MAX MODULES is reached");
        uint256 moduleCost = moduleFactory.setupCost();
        require(moduleCost <= _maxCost, "Max Cost is always be greater than module cost");
        //Approve fee for module
        require(ERC20(IRegistry(securityTokenRegistry).getAddress("PolyToken")).approve(_moduleFactory, moduleCost), "Not able to approve the module cost");
        //Creates instance of module from factory
        address module = moduleFactory.deploy(_data);
        //Approve ongoing budget
        require(ERC20(IRegistry(securityTokenRegistry).getAddress("PolyToken")).approve(module, _budget), "Not able to approve the budget");
        //Add to SecurityToken module map
        modules[moduleFactory.getType()].push(ModuleData(moduleFactory.getName(), module));
        //Emit log event
        emit LogModuleAdded(moduleFactory.getType(), moduleFactory.getName(), _moduleFactory, module, moduleCost, _budget, now);
    }

    /**
    * @notice Removes a module attached to the SecurityToken
    * @param _moduleType is which type of module we are trying to remove
    * @param _moduleIndex is the index of the module within the chosen type
    */
    function removeModule(uint8 _moduleType, uint8 _moduleIndex) external onlyOwner {
        require(_moduleIndex < modules[_moduleType].length,
        "Module index doesn't exist as per the choosen module type");
        require(modules[_moduleType][_moduleIndex].moduleAddress != address(0),
        "Module contract address should not be 0x");
        //Take the last member of the list, and replace _moduleIndex with this, then shorten the list by one
        emit LogModuleRemoved(_moduleType, modules[_moduleType][_moduleIndex].moduleAddress, now);
        modules[_moduleType][_moduleIndex] = modules[_moduleType][modules[_moduleType].length - 1];
        modules[_moduleType].length = modules[_moduleType].length - 1;
    }

    /**
     * @notice Returns module list for a module type
     * @param _moduleType is which type of module we are trying to get
     * @param _moduleIndex is the index of the module within the chosen type
     * @return bytes32
     * @return address
     */
    function getModule(uint8 _moduleType, uint _moduleIndex) public returns (bytes32, address) {
        if (modules[_moduleType].length > 0) {
            return (
                modules[_moduleType][_moduleIndex].name,
                modules[_moduleType][_moduleIndex].moduleAddress
            );
        } else {
            return ("", address(0));
        }

    }

    /**
     * @notice returns module list for a module name - will return first match
     * @param _moduleType is which type of module we are trying to get
     * @param _name is the name of the module within the chosen type
     * @return bytes32
     * @return address
     */
    function getModuleByName(uint8 _moduleType, bytes32 _name) public returns (bytes32, address) {
        if (modules[_moduleType].length > 0) {
            for (uint256 i = 0; i < modules[_moduleType].length; i++) {
                if (modules[_moduleType][i].name == _name) {
                  return (
                      modules[_moduleType][i].name,
                      modules[_moduleType][i].moduleAddress
                  );
                }
            }
            return ("", address(0));
        } else {
            return ("", address(0));
        }
    }

    /**
    * @notice allows the owner to withdraw unspent POLY stored by them on the ST.
    * @dev Owner can transfer POLY to the ST which will be used to pay for modules that require a POLY fee.
    * @param _amount amount of POLY to withdraw
    */
    function withdrawPoly(uint256 _amount) public onlyOwner {
        require(ERC20(IRegistry(securityTokenRegistry).getAddress("PolyToken")).transfer(owner, _amount), "In-sufficient balance");
    }

    /**
    * @notice allows owner to approve more POLY to one of the modules
    * @param _moduleType module type
    * @param _moduleIndex module index
    * @param _budget new budget
    */
    function changeModuleBudget(uint8 _moduleType, uint8 _moduleIndex, uint256 _budget) public onlyOwner {
        require(_moduleType != 0, "Module type cannot be zero");
        require(_moduleIndex < modules[_moduleType].length, "Incorrrect module index");
        require(ERC20(IRegistry(securityTokenRegistry).getAddress("PolyToken")).approve(modules[_moduleType][_moduleIndex].moduleAddress, _budget), "Insufficient balance to approve");
        emit LogModuleBudgetChanged(_moduleType, modules[_moduleType][_moduleIndex].moduleAddress, _budget);
    }

    /**
     * @notice change the tokenDetails
     * @param _newTokenDetails New token details
     */
    function updateTokenDetails(string _newTokenDetails) public onlyOwner {
        emit LogUpdateTokenDetails(tokenDetails, _newTokenDetails);
        tokenDetails = _newTokenDetails;
    }

    /**
    * @notice allows owner to change token granularity
    * @param _granularity granularity level of the token
    */
    function changeGranularity(uint256 _granularity) public onlyOwner {
        require(_granularity != 0, "Granularity can not be 0");
        emit LogGranularityChanged(granularity, _granularity);
        granularity = _granularity;
    }

    /**
    * @notice keeps track of the number of non-zero token holders
    * @param _from sender of transfer
    * @param _to receiver of transfer
    * @param _value value of transfer
    */
    function adjustInvestorCount(address _from, address _to, uint256 _value) internal {
        if ((_value == 0) || (_from == _to)) {
            return;
        }
        // Check whether receiver is a new token holder
        if ((balanceOf(_to) == 0) && (_to != address(0))) {
            investorCount = investorCount.add(1);
        }
        // Check whether sender is moving all of their tokens
        if (_value == balanceOf(_from)) {
            investorCount = investorCount.sub(1);
        }
        //Also adjust investor list
        if (!investorListed[_to] && (_to != address(0))) {
            investors.push(_to);
            investorListed[_to] = true;
        }

    }

    /**
    * @notice removes addresses with zero balances from the investors list
    * @param _start Index in investor list at which to start removing zero balances
    * @param _iters Max number of iterations of the for loop
    * NB - pruning this list will mean you may not be able to iterate over investors on-chain as of a historical checkpoint
    */
    function pruneInvestors(uint256 _start, uint256 _iters) public onlyOwner {
        for (uint256 i = _start; i < Math.min256(_start.add(_iters), investors.length); i++) {
            if ((i < investors.length) && (balanceOf(investors[i]) == 0)) {
                investorListed[investors[i]] = false;
                investors[i] = investors[investors.length - 1];
                investors.length--;
            }
        }
    }

    /**
     * @notice gets length of investors array
     * NB - this length may differ from investorCount if list has not been pruned of zero balance investors
     * @return length
     */
    function getInvestorsLength() public view returns(uint256) {
        return investors.length;
    }

    /**
     * @notice freeze all the transfers
     */
    function freezeTransfers() public onlyOwner {
        require(!freeze);
        freeze = true;
        emit LogFreezeTransfers(freeze, now);
    }

    /**
     * @notice un-freeze all the transfers
     */
    function unfreezeTransfers() public onlyOwner {
        require(freeze);
        freeze = false;
        emit LogFreezeTransfers(freeze, now);
    }

    /**
     * @notice adjust totalsupply at checkpoint after minting or burning tokens
     */
    function adjustTotalSupplyCheckpoints() internal {
        adjustCheckpoints(checkpointTotalSupply, totalSupply());
    }

    /**
     * @notice adjust token holder balance at checkpoint after a token transfer
     * @param _investor address of the token holder affected
     */
    function adjustBalanceCheckpoints(address _investor) internal {
        adjustCheckpoints(checkpointBalances[_investor], balanceOf(_investor));
    }

    /**
     * @notice store the changes to the checkpoint objects
     * @param _checkpoints the affected checkpoint object array
     * @param _newValue the new value that needs to be stored
     */
    function adjustCheckpoints(Checkpoint[] storage _checkpoints, uint256 _newValue) internal {
        //No checkpoints set yet
        if (currentCheckpointId == 0) {
            return;
        }
        //No previous checkpoint data - add current balance against checkpoint
        if (_checkpoints.length == 0) {
            _checkpoints.push(
                Checkpoint({
                    checkpointId: currentCheckpointId,
                    value: _newValue
                })
            );
            return;
        }
        //No new checkpoints since last update
        if (_checkpoints[_checkpoints.length - 1].checkpointId == currentCheckpointId) {
            return;
        }
        //New checkpoint, so record balance
        _checkpoints.push(
            Checkpoint({
                checkpointId: currentCheckpointId,
                value: _newValue
            })
        );
    }

    /**
     * @notice Overloaded version of the transfer function
     * @param _to receiver of transfer
     * @param _value value of transfer
     * @return bool success
     */
    function transfer(address _to, uint256 _value) public returns (bool success) {
        adjustInvestorCount(msg.sender, _to, _value);
        require(verifyTransfer(msg.sender, _to, _value), "Transfer is not valid");
        adjustBalanceCheckpoints(msg.sender);
        adjustBalanceCheckpoints(_to);
        require(super.transfer(_to, _value));
        return true;
    }

    /**
     * @notice Overloaded version of the transferFrom function
     * @param _from sender of transfer
     * @param _to receiver of transfer
     * @param _value value of transfer
     * @return bool success
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        adjustInvestorCount(_from, _to, _value);
        require(verifyTransfer(_from, _to, _value), "Transfer is not valid");
        adjustBalanceCheckpoints(_from);
        adjustBalanceCheckpoints(_to);
        require(super.transferFrom(_from, _to, _value));
        return true;
    }

    /**
     * @notice validate transfer with TransferManager module if it exists
     * @dev TransferManager module has a key of 2
     * @param _from sender of transfer
     * @param _to receiver of transfer
     * @param _amount value of transfer
     * @return bool
     */
    function verifyTransfer(address _from, address _to, uint256 _amount) public checkGranularity(_amount) returns (bool) {
        if (!freeze) {
            bool isTransfer = false;
            if (transferFunctions[getSig(msg.data)]) {
              isTransfer = true;
            }
            if (modules[TRANSFERMANAGER_KEY].length == 0) {
                return true;
            }
            bool isInvalid = false;
            bool isValid = false;
            bool isForceValid = false;
            for (uint8 i = 0; i < modules[TRANSFERMANAGER_KEY].length; i++) {
                ITransferManager.Result valid = ITransferManager(modules[TRANSFERMANAGER_KEY][i].moduleAddress).verifyTransfer(_from, _to, _amount, isTransfer);
                if (valid == ITransferManager.Result.INVALID) {
                    isInvalid = true;
                }
                if (valid == ITransferManager.Result.VALID) {
                    isValid = true;
                }
                if (valid == ITransferManager.Result.FORCE_VALID) {
                    isForceValid = true;
                }
            }
            return isForceValid ? true : (isInvalid ? false : isValid);
      }
      return false;
    }

    /**
     * @notice End token minting period permanently for Issuer
     */
    function finishMintingIssuer() public onlyOwner {
        finishedIssuerMinting = true;
        emit LogFinishMintingIssuer(now);
    }

    /**
     * @notice End token minting period permanently for STOs
     */
    function finishMintingSTO() public onlyOwner {
        finishedSTOMinting = true;
        emit LogFinishMintingSTO(now);
    }

    /**
     * @notice mints new tokens and assigns them to the target _investor.
     * @dev Can only be called by the STO attached to the token (Or by the ST owner if there's no STO attached yet)
     * @param _investor Address to whom the minted tokens will be dilivered
     * @param _amount Number of tokens get minted
     * @return success
     */
    function mint(address _investor, uint256 _amount) public onlyModule(STO_KEY, true) checkGranularity(_amount) isMintingAllowed() returns (bool success) {
        adjustInvestorCount(address(0), _investor, _amount);
        require(verifyTransfer(address(0), _investor, _amount), "Transfer is not valid");
        adjustBalanceCheckpoints(_investor);
        adjustTotalSupplyCheckpoints();
        totalSupply_ = totalSupply_.add(_amount);
        balances[_investor] = balances[_investor].add(_amount);
        emit Minted(_investor, _amount);
        emit Transfer(address(0), _investor, _amount);
        return true;
    }

    /**
     * @notice mints new tokens and assigns them to the target _investor.
     * Can only be called by the STO attached to the token (Or by the ST owner if there's no STO attached yet)
     * @param _investors A list of addresses to whom the minted tokens will be dilivered
     * @param _amounts A list of number of tokens get minted and transfer to corresponding address of the investor from _investor[] list
     * @return success
     */
    function mintMulti(address[] _investors, uint256[] _amounts) public onlyModule(STO_KEY, true) returns (bool success) {
        require(_investors.length == _amounts.length, "Mis-match in the length of the arrays");
        for (uint256 i = 0; i < _investors.length; i++) {
            mint(_investors[i], _amounts[i]);
        }
        return true;
    }

    /**
     * @notice Validate permissions with PermissionManager if it exists, If no Permission return false
     * @dev Note that IModule withPerm will allow ST owner all permissions anyway
     * @dev this allows individual modules to override this logic if needed (to not allow ST owner all permissions)
     * @param _delegate address of delegate
     * @param _module address of PermissionManager module
     * @param _perm the permissions
     * @return success
     */
    function checkPermission(address _delegate, address _module, bytes32 _perm) public view returns(bool) {
        if (modules[PERMISSIONMANAGER_KEY].length == 0) {
            return false;
        }

        for (uint8 i = 0; i < modules[PERMISSIONMANAGER_KEY].length; i++) {
            if (IPermissionManager(modules[PERMISSIONMANAGER_KEY][i].moduleAddress).checkPermission(_delegate, _module, _perm)) {
                return true;
            }
        }
    }

    /**
     * @notice used to set the token Burner address. It only be called by the owner
     * @param _tokenBurner Address of the token burner contract
     */
    function setTokenBurner(address _tokenBurner) public onlyOwner {
        tokenBurner = ITokenBurner(_tokenBurner);
    }

    /**
     * @notice Burn function used to burn the securityToken
     * @param _value No. of token that get burned
     */
    function burn(uint256 _value) checkGranularity(_value) public {
        adjustInvestorCount(msg.sender, address(0), _value);
        require(tokenBurner != address(0), "Token Burner contract address is not set yet");
        require(verifyTransfer(msg.sender, address(0), _value), "Transfer is not valid");
        require(_value <= balances[msg.sender], "Value should no be greater than the balance of msg.sender");
        adjustBalanceCheckpoints(msg.sender);
        adjustTotalSupplyCheckpoints();
        // no need to require value <= totalSupply, since that would imply the
        // sender's balance is greater than the totalSupply, which *should* be an assertion failure

        balances[msg.sender] = balances[msg.sender].sub(_value);
        require(tokenBurner.burn(msg.sender, _value), "Token burner process is not validated");
        totalSupply_ = totalSupply_.sub(_value);
        emit Burnt(msg.sender, _value);
        emit Transfer(msg.sender, address(0), _value);
    }

    /**
     * @notice Get function signature from _data
     * @param _data passed data
     * @return bytes4 sig
     */
    function getSig(bytes _data) internal pure returns (bytes4 sig) {
        uint len = _data.length < 4 ? _data.length : 4;
        for (uint i = 0; i < len; i++) {
            sig = bytes4(uint(sig) + uint(_data[i]) * (2 ** (8 * (len - 1 - i))));
        }
    }

    /**
     * @notice set a new Security Token Registry contract address in case of upgrade
     * @param _newAddress is address of new contract
     */
     function changeSecurityTokenRegistryAddress(address _newAddress) public onlyOwner {
         require(_newAddress != securityTokenRegistry && _newAddress != address(0));
         emit LogChangeSTRAddress(securityTokenRegistry, _newAddress);
         securityTokenRegistry = _newAddress;
     }

    /**
     * @notice Creates a checkpoint that can be used to query historical balances / totalSuppy
     * @return uint256
     */
    function createCheckpoint() public onlyModule(CHECKPOINT_KEY, true) returns(uint256) {
        require(currentCheckpointId < 2**256 - 1);
        currentCheckpointId = currentCheckpointId + 1;
        emit LogCheckpointCreated(currentCheckpointId, now);
        return currentCheckpointId;
    }

    /**
     * @notice Queries totalSupply as of a defined checkpoint
     * @param _checkpointId Checkpoint ID to query
     * @return uint256
     */
    function totalSupplyAt(uint256 _checkpointId) public view returns(uint256) {
        return getValueAt(checkpointTotalSupply, _checkpointId, totalSupply());
    }

    /**
     * @notice Queries value at a defined checkpoint
     * @param checkpoints is array of Checkpoint objects
     * @param _checkpointId Checkpoint ID to query
     * @param _currentValue Current value of checkpoint
     * @return uint256
     */
    function getValueAt(Checkpoint[] storage checkpoints, uint256 _checkpointId, uint256 _currentValue) internal view returns(uint256) {
        require(_checkpointId <= currentCheckpointId);
        //Checkpoint id 0 is when the token is first created - everyone has a zero balance
        if (_checkpointId == 0) {
          return 0;
        }
        if (checkpoints.length == 0) {
            return _currentValue;
        }
        if (checkpoints[0].checkpointId >= _checkpointId) {
            return checkpoints[0].value;
        }
        if (checkpoints[checkpoints.length - 1].checkpointId < _checkpointId) {
            return _currentValue;
        }
        if (checkpoints[checkpoints.length - 1].checkpointId == _checkpointId) {
            return checkpoints[checkpoints.length - 1].value;
        }
        uint256 min = 0;
        uint256 max = checkpoints.length - 1;
        while (max > min) {
            uint256 mid = (max + min) / 2;
            if (checkpoints[mid].checkpointId == _checkpointId) {
                max = mid;
                break;
            }
            if (checkpoints[mid].checkpointId < _checkpointId) {
                min = mid + 1;
            } else {
                max = mid;
            }
        }
        return checkpoints[max].value;
    }

    /**
     * @notice Queries balances as of a defined checkpoint
     * @param _investor Investor to query balance for
     * @param _checkpointId Checkpoint ID to query as of
     */
    function balanceOfAt(address _investor, uint256 _checkpointId) public view returns(uint256) {
        return getValueAt(checkpointBalances[_investor], _checkpointId, balanceOf(_investor));
    }

}

/**
 * @title Proxy for deploying Security Token v1
 */
contract STVersionProxy001 is ISTProxy {

    address public transferManagerFactory;

    // Should be set to false when we have more TransferManager options
    bool addTransferManager = true;

    constructor (address _transferManagerFactory) public {
        transferManagerFactory = _transferManagerFactory;
    }

    /**
     * @notice deploys the token and adds default modules like permission manager and transfer manager.
     * Future versions of the proxy can attach different modules or pass some other paramters.
     */
    function deployToken(string _name, string _symbol, uint8 _decimals, string _tokenDetails, address _issuer, bool _divisible)
    public returns (address) {
        address newSecurityTokenAddress = new SecurityToken(
        _name,
        _symbol,
        _decimals,
        _divisible ? 1 : uint256(10)**_decimals,
        _tokenDetails,
        msg.sender
        );

        if (addTransferManager) {
            SecurityToken(newSecurityTokenAddress).addModule(transferManagerFactory, "", 0, 0);
        }

        SecurityToken(newSecurityTokenAddress).transferOwnership(_issuer);

        return newSecurityTokenAddress;
    }
}

