// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/IERC721Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC1155/IERC1155Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165StorageUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol";

import "@openzeppelin/contracts-upgradeable/utils/CountersUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";

import "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721URIStorageUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721EnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721BurnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721PausableUpgradeable.sol";

import "@openzeppelin/contracts-upgradeable/token/ERC1155/ERC1155Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC1155/extensions/ERC1155BurnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC1155/extensions/ERC1155PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC1155/extensions/ERC1155SupplyUpgradeable.sol";

library BytesLibrary {
    function toString(bytes32 value) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            str[i*2] = alphabet[uint8(value[i] >> 4)];
            str[1+i*2] = alphabet[uint8(value[i] & 0x0f)];
        }
        return string(str);
    }
}


library UintLibrary {
    using SafeMathUpgradeable for uint;

    function toString(uint256 _i) internal pure returns (string memory) {
        if (_i == 0) {
            return "0";
        }
        uint j = _i;
        uint len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint k = len;
        while (_i != 0) {
            k = k-1;
            uint8 temp = (48 + uint8(_i - _i / 10 * 10));
            bytes1 b1 = bytes1(temp);
            bstr[k] = b1;
            _i /= 10;
        }
        return string(bstr);
    }

    function bp(uint value, uint bpValue) internal pure returns (uint) {
        return value.mul(bpValue).div(10000);
    }
}

library StringLibrary {
    using UintLibrary for uint256;

    function append(string memory a, string memory b) internal pure returns (string memory) {
        bytes memory ba = bytes(a);
        bytes memory bb = bytes(b);
        bytes memory bab = new bytes(ba.length + bb.length);
        uint k = 0;
        for (uint i = 0; i < ba.length; i++) bab[k++] = ba[i];
        for (uint i = 0; i < bb.length; i++) bab[k++] = bb[i];
        return string(bab);
    }

    function append(string memory a, string memory b, string memory c) internal pure returns (string memory) {
        bytes memory ba = bytes(a);
        bytes memory bb = bytes(b);
        bytes memory bc = bytes(c);
        bytes memory bbb = new bytes(ba.length + bb.length + bc.length);
        uint k = 0;
        for (uint i = 0; i < ba.length; i++) bbb[k++] = ba[i];
        for (uint i = 0; i < bb.length; i++) bbb[k++] = bb[i];
        for (uint i = 0; i < bc.length; i++) bbb[k++] = bc[i];
        return string(bbb);
    }

    function recover(string memory message, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        bytes memory msgBytes = bytes(message);
        bytes memory fullMessage = concat(
            bytes("\x19Ethereum Signed Message:\n"),
            bytes(msgBytes.length.toString()),
            msgBytes,
            new bytes(0), new bytes(0), new bytes(0), new bytes(0)
        );
        return ecrecover(keccak256(fullMessage), v, r, s);
    }

    function concat(bytes memory ba, bytes memory bb, bytes memory bc, bytes memory bd, bytes memory be, bytes memory bf, bytes memory bg) internal pure returns (bytes memory) {
        bytes memory resultBytes = new bytes(ba.length + bb.length + bc.length + bd.length + be.length + bf.length + bg.length);
        uint k = 0;
        for (uint i = 0; i < ba.length; i++) resultBytes[k++] = ba[i];
        for (uint i = 0; i < bb.length; i++) resultBytes[k++] = bb[i];
        for (uint i = 0; i < bc.length; i++) resultBytes[k++] = bc[i];
        for (uint i = 0; i < bd.length; i++) resultBytes[k++] = bd[i];
        for (uint i = 0; i < be.length; i++) resultBytes[k++] = be[i];
        for (uint i = 0; i < bf.length; i++) resultBytes[k++] = bf[i];
        for (uint i = 0; i < bg.length; i++) resultBytes[k++] = bg[i];
        return resultBytes;
    }
}

library Roles {
    struct Role {
        mapping (address => bool) bearer;
    }

    /**
     * @dev Give an account access to this role.
     */
    function add(Role storage role, address account) internal {
        require(!has(role, account), "Roles: account already has role");
        role.bearer[account] = true;
    }

    /**
     * @dev Remove an account's access to this role.
     */
    function remove(Role storage role, address account) internal {
        require(has(role, account), "Roles: account does not have role");
        role.bearer[account] = false;
    }

    /**
     * @dev Check if an account has this role.
     * @return bool
     */
    function has(Role storage role, address account) internal view returns (bool) {
        require(account != address(0), "Roles: account is the zero address");
        return role.bearer[account];
    }
}

contract OperatorRole is ContextUpgradeable {
    using Roles for Roles.Role;

    event OperatorAdded(address indexed account);
    event OperatorRemoved(address indexed account);

    Roles.Role private _operators;

    modifier onlyOperator() {
        require(isOperator(_msgSender()), "OperatorRole: caller does not have the Operator role");
        _;
    }

    function isOperator(address account) public view returns (bool) {
        return _operators.has(account);
    }

    function _addOperator(address account) internal {
        _operators.add(account);
        emit OperatorAdded(account);
    }

    function _removeOperator(address account) internal {
        _operators.remove(account);
        emit OperatorRemoved(account);
    }
}

contract OwnableOperatorRole is OwnableUpgradeable, OperatorRole {
    function addOperator(address account) external onlyOwner {
        _addOperator(account);
    }

    function removeOperator(address account) external onlyOwner {
        _removeOperator(account);
    }
}

contract ERC20TransferProxy is OwnableOperatorRole {

    function initialize() 
        initializer 
        public 
        virtual 
    {

        __Ownable_init_unchained();
        __Context_init_unchained();
        
        __ERC20TransferProxy_init_unchained();
    }

    function __ERC20TransferProxy_init_unchained() 
        internal 
        initializer 
        virtual 
    {
        
    }

    function erc20safeTransferFrom(IERC20Upgradeable token, address from, address to, uint256 value) external onlyOperator {
        require(token.transferFrom(from, to, value), "failure while transferring");
    }

    function version() public virtual pure returns (string memory) {
        return "v1";
    }
}

abstract contract HasRoyaltyFees is ERC165StorageUpgradeable {

    event SecondarySaleFees(uint256 tokenId, address[] recipients, uint[] bps);

    /*
     * bytes4(keccak256('getFeeBps(uint256)')) == 0x0ebd4c7f
     * bytes4(keccak256('getFeeRecipients(uint256)')) == 0xb9c4d9fb
     *
     * => 0x0ebd4c7f ^ 0xb9c4d9fb == 0xb7799584
     */
    bytes4 private constant _INTERFACE_ID_FEES = 0xb7799584;

    function initialize() initializer public virtual {

        __ERC165_init_unchained();

        __HasRoyaltyFees_init_unchained();
    }

    function __HasRoyaltyFees_init_unchained() internal initializer virtual {
        _registerInterface(_INTERFACE_ID_FEES);
    }

    function getFeeRecipients(uint256 id) external view virtual returns (address payable[] memory);
    function getFeeBps(uint256 id) external view virtual returns (uint[] memory);
}

contract INNODomain {
    enum AssetType {ETH, ERC20}
    
    struct StorageFee {
        AssetType assetType;
        address token;
        uint256 fee;
    }

    event StorageFeeEvent(
        uint256 indexed tokenId,
        address indexed feeBeneficiary,
        StorageFee storageFee
    );

    // royalty fee
    struct Fee {
        address payable recipient;  // receiver wallet address
        uint256 feeBPS;  // fee value ( in basis point (bps), 1 BPS = 0.01% )
    }
}

contract INNO721 is 
    INNODomain,
    AccessControlEnumerableUpgradeable, 
    ERC721URIStorageUpgradeable, 
    ERC721EnumerableUpgradeable, 
    ERC721BurnableUpgradeable,
    ERC721PausableUpgradeable,
    HasRoyaltyFees,
    OwnableOperatorRole
{
    using CountersUpgradeable for CountersUpgradeable.Counter;
    CountersUpgradeable.Counter private _tokenIds;

    ERC20TransferProxy public erc20TransferProxy;
    address payable public beneficiary;
    StorageFee public storageFee;

    // token id => fees
    mapping (uint256 => Fee[]) public fees;

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    function initialize(
        string memory _name,
        string memory _symbol,
        ERC20TransferProxy _erc20TransferProxy,
        address payable _beneficiary
    ) initializer public virtual {

        __Ownable_init_unchained();
        __Context_init_unchained();
        __ERC165_init_unchained();
        __HasRoyaltyFees_init_unchained();
        __AccessControl_init_unchained();
        __AccessControlEnumerable_init_unchained();
        __ERC721_init_unchained(_name, _symbol);
        __ERC721Enumerable_init_unchained();
        __ERC721Burnable_init_unchained();
        __Pausable_init_unchained();
        __ERC721Pausable_init_unchained();
        __ERC721URIStorage_init_unchained();

        __INNO721_init_unchained();

        erc20TransferProxy = _erc20TransferProxy;
        beneficiary = _beneficiary;
    }

    function __INNO721_init_unchained() internal initializer virtual {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());

        _setupRole(MINTER_ROLE, _msgSender());
        _setupRole(PAUSER_ROLE, _msgSender());
    }

    // create a token and transfer to an address
    function mint(string memory _tokenURI, Fee[] memory _fees) 
        public 
        virtual 
        payable
        returns (uint256) 
    {
        // require(hasRole(MINTER_ROLE, _msgSender()), "INNO721: must have minter role to mint");
        
        uint256 newItemId = _tokenIds.current();
        _mint(msg.sender, newItemId);
        _setTokenURI(newItemId, _tokenURI);
        _tokenIds.increment();


        address[] memory recipients = new address[](_fees.length);
        uint[] memory feeBPSs = new uint[](_fees.length);

        for (uint i = 0; i < _fees.length; i++) {
            require(_fees[i].recipient != address(0x0), "Recipient should be present");
            require(_fees[i].feeBPS != 0, "Fee value should be positive");
            fees[newItemId].push(_fees[i]);
            recipients[i] = _fees[i].recipient;
            feeBPSs[i] = _fees[i].feeBPS;
        }
        if (_fees.length > 0) {
            emit SecondarySaleFees (newItemId, recipients, feeBPSs);
        }

        if(storageFee.fee > 0) {
            transferStorageFee(storageFee.assetType, storageFee.token, storageFee.fee, msg.sender, beneficiary);
        }

        emit StorageFeeEvent(newItemId, beneficiary, storageFee);

        return newItemId;
    }

    function transferStorageFee(
        AssetType assetType, 
        address token,
        uint value, 
        address from, 
        address to) 
        virtual 
        internal 
    {
        require(assetType == AssetType.ETH || assetType == AssetType.ERC20, "Only BNB or BEP20 are accepted for storage fee");

        if (assetType == AssetType.ETH) {
            AddressUpgradeable.sendValue(payable(to), value);
        } else if (assetType == AssetType.ERC20) {
            erc20TransferProxy.erc20safeTransferFrom(IERC20Upgradeable(token), from, to, value);
        }
    }

    function setBeneficiary(address payable newBeneficiary) virtual external onlyOwner {
        beneficiary = newBeneficiary;
    }

    function setStorageFee(INNODomain.StorageFee calldata _storageFee) virtual external onlyOperator {
        storageFee = _storageFee;
    }

    function getFeeRecipients(uint256 id) public override virtual view returns (address payable[] memory) {
        Fee[] memory _fees = fees[id];
        address payable[] memory result = new address payable[](_fees.length);
        for (uint i = 0; i < _fees.length; i++) {
            result[i] = _fees[i].recipient;
        }
        return result;
    }

    function getFeeBps(uint256 id) public override virtual view returns (uint[] memory) {
        Fee[] memory _fees = fees[id];
        uint[] memory result = new uint[](_fees.length);
        for (uint i = 0; i < _fees.length; i++) {
            result[i] = _fees[i].feeBPS;
        }
        return result;
    }

    function pause() public virtual {
        require(hasRole(PAUSER_ROLE, _msgSender()), "INNO721: must have pauser role to pause");
        _pause();
    }

    function unpause() public virtual {
        require(hasRole(PAUSER_ROLE, _msgSender()), "INNO721: must have pauser role to unpause");
        _unpause();
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(AccessControlEnumerableUpgradeable, ERC721EnumerableUpgradeable, ERC721Upgradeable, ERC165StorageUpgradeable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _burn(
        uint256 tokenId
    ) internal virtual override (ERC721URIStorageUpgradeable, ERC721Upgradeable) {
        super._burn(tokenId);
    }

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual override (ERC721EnumerableUpgradeable, ERC721PausableUpgradeable, ERC721Upgradeable) {
        super._beforeTokenTransfer(from, to, tokenId);
    }

    function tokenURI(
        uint256 tokenId
    ) public view virtual override (ERC721URIStorageUpgradeable, ERC721Upgradeable) returns (string memory) {
        return super.tokenURI(tokenId);
    }

    function version() public virtual pure returns (string memory) {
        return "v1";
    }
}

contract INNO1155 is 
    INNODomain,
    Initializable, 
    ContextUpgradeable, 
    AccessControlEnumerableUpgradeable, 
    ERC1155BurnableUpgradeable, 
    ERC1155PausableUpgradeable,
    ERC1155SupplyUpgradeable,
    HasRoyaltyFees,
    OwnableOperatorRole
{
    using CountersUpgradeable for CountersUpgradeable.Counter;
    CountersUpgradeable.Counter private _tokenIds;

    ERC20TransferProxy public erc20TransferProxy;
    address payable public beneficiary;
    StorageFee public storageFee;

    // token id => fees
    mapping (uint256 => Fee[]) public fees;

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    string public __name;
    string public __symbol;

    mapping(uint256 => string) private _tokenURIs;

    function initialize(
        string memory _name,
        string memory _symbol,
        ERC20TransferProxy _erc20TransferProxy,
        address payable _beneficiary
    ) initializer public virtual {

        __Ownable_init_unchained();
        __Context_init_unchained();
        __ERC165_init_unchained();
        __HasRoyaltyFees_init_unchained();
        __AccessControl_init_unchained();
        __AccessControlEnumerable_init_unchained();
        __ERC1155_init_unchained("");
        __ERC1155Burnable_init_unchained();
        __Pausable_init_unchained();
        __ERC1155Pausable_init_unchained();
        __ERC1155Supply_init_unchained();

        __INNO1155_init_unchained(_name, _symbol);

        erc20TransferProxy = _erc20TransferProxy;
        beneficiary = _beneficiary;
    }

    function __INNO1155_init_unchained(
        string memory _name,
        string memory _symbol) 
        internal
        initializer 
        virtual
    {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());

        _setupRole(MINTER_ROLE, _msgSender());
        _setupRole(PAUSER_ROLE, _msgSender());

        __name = _name;
        __symbol = _symbol;
    }

    function name() public view virtual returns (string memory) {
        return __name;
    }
    
    function symbol() public view virtual returns (string memory) {
        return __symbol;
    }

    function mint(
        string memory tokenURI, 
        uint256 supply, 
        bytes memory data,
        Fee[] memory _fees) 
        public 
        virtual
        payable
        returns (uint256)
    {
        // require(hasRole(MINTER_ROLE, _msgSender()), "Need minter role");
        require(bytes(tokenURI).length > 0, "TokenURI is empty");
        require(supply != 0, "Supply is 0");

        uint256 newTokenId = _tokenIds.current();
        _mint(msg.sender, newTokenId, supply, data);
        _setTokenURI(newTokenId, tokenURI);
        _tokenIds.increment();
        
        address[] memory recipients = new address[](_fees.length);
        uint[] memory bps = new uint[](_fees.length);
        for (uint i = 0; i < _fees.length; i++) {
            require(_fees[i].recipient != address(0x0), "Recipient should be present");
            require(_fees[i].feeBPS != 0, "Fee value should be positive");
            fees[newTokenId].push(_fees[i]);
            recipients[i] = _fees[i].recipient;
            bps[i] = _fees[i].feeBPS;
        }
        if (_fees.length > 0) {
            emit SecondarySaleFees(newTokenId, recipients, bps);
        }

        if(storageFee.fee > 0) {
            transferStorageFee(storageFee.assetType, storageFee.token, storageFee.fee, msg.sender, beneficiary);
        }

        emit StorageFeeEvent(newTokenId, beneficiary, storageFee);

        // if(_storageFees.length > 0) {
        //     for (uint i = 0; i < _storageFees.length; i++) {
        //         transferStorageFee(_storageFees[i].assetType, _storageFees[i].token, _storageFees[i].fee, msg.sender, beneficiary);
        //     }
        //     emit StorageFeeEvent(newTokenId, beneficiary, _storageFees);
        // }

        return newTokenId;
    }

    function transferStorageFee(
        AssetType assetType, 
        address token,
        uint value, 
        address from, 
        address to) 
        virtual 
        internal 
    {
        require(assetType == AssetType.ETH || assetType == AssetType.ERC20, "Only BNB or BEP20 are accepted for storage fee");

        if (assetType == AssetType.ETH) {
            AddressUpgradeable.sendValue(payable(to), value);
        } else if (assetType == AssetType.ERC20) {
            erc20TransferProxy.erc20safeTransferFrom(IERC20Upgradeable(token), from, to, value);
        }
    }

    function setBeneficiary(address payable newBeneficiary) virtual external onlyOwner {
        beneficiary = newBeneficiary;
    }

    function setStorageFee(INNODomain.StorageFee calldata _storageFee) virtual external onlyOperator {
        storageFee = _storageFee;
    }

    function getFeeRecipients(uint256 id) public override view returns (address payable[] memory) {
        Fee[] memory _fees = fees[id];
        address payable[] memory result = new address payable[](_fees.length);
        for (uint i = 0; i < _fees.length; i++) {
            result[i] = _fees[i].recipient;
        }
        return result;
    }

    function getFeeBps(uint256 id) public override view returns (uint[] memory) {
        Fee[] memory _fees = fees[id];
        uint[] memory result = new uint[](_fees.length);
        for (uint i = 0; i < _fees.length; i++) {
            result[i] = _fees[i].feeBPS;
        }
        return result;
    }

    function mintBatch(
        string[] memory tokenURIs, 
        uint256[] memory supplys,
        bytes memory data,
        Fee[][] memory _fees) 
        public 
        virtual 
        returns (uint256[] memory)
    {
        //require(hasRole(MINTER_ROLE, _msgSender()), "Need minter role");
        require(tokenURIs.length == supplys.length, "URIs & Supplys mismatch");
        require(tokenURIs.length > 0, "URIs is empty");

        uint256[] memory newTokenIds = new uint256[](tokenURIs.length);
        for (uint i = 0; i < tokenURIs.length; i++)
        {
            require(bytes(tokenURIs[i]).length > 0, "TokenURI should be set");
            require(supplys[i] != 0, "Supply is 0");

            uint256 newTokenId = _tokenIds.current();
            newTokenIds[i] = newTokenId;

            _tokenIds.increment();

            address[] memory recipients = new address[](_fees[i].length);
            uint[] memory bps = new uint[](_fees[i].length);
            for (uint j = 0; j < _fees[i].length; j++) {
                require(_fees[i][j].recipient != address(0x0), "Recipient should be present");
                require(_fees[i][j].feeBPS != 0, "Fee value should be positive");
                fees[newTokenId].push(_fees[i][j]);
                recipients[j] = _fees[i][j].recipient;
                bps[j] = _fees[i][j].feeBPS;
            }
            if (_fees[i].length > 0) {
                emit SecondarySaleFees(newTokenId, recipients, bps);
            }

            if(storageFee.fee > 0) {
                transferStorageFee(storageFee.assetType, storageFee.token, storageFee.fee, msg.sender, beneficiary);
            }
            emit StorageFeeEvent(newTokenId, beneficiary, storageFee);
        }

        _mintBatch(msg.sender, newTokenIds, supplys, data);
        _setTokenURIs(newTokenIds, tokenURIs);

        return newTokenIds;
    }

    function uri(uint256 tokenId) public view virtual override returns (string memory) 
    {
        require(_exists(tokenId), "TokenId not exist");

        string memory _tokenURI = _tokenURIs[tokenId];

        if (bytes(_tokenURI).length != 0) 
        {
            return _tokenURI;
        }

        return super.uri(tokenId);
    }

    function pause() public virtual {
        require(hasRole(PAUSER_ROLE, _msgSender()), "Need pauser role");
        _pause();
    }

    function unpause() public virtual {
        require(hasRole(PAUSER_ROLE, _msgSender()), "Need pauser role");
        _unpause();
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(AccessControlEnumerableUpgradeable, ERC1155Upgradeable, ERC165StorageUpgradeable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _setTokenURI(uint256 tokenId, string memory _tokenURI) internal virtual {
        require(_exists(tokenId), "TokenId not exist");
        _tokenURIs[tokenId] = _tokenURI;
    }

    function _setTokenURIs(uint256[] memory tokenIds, string[] memory tokenURIs) internal virtual {
        for (uint i = 0; i < tokenURIs.length; i++)
        {
            require(_exists(tokenIds[i]), "TokenId not exist");
            _tokenURIs[tokenIds[i]] = tokenURIs[i];
        }
    }

    function _exists(uint256 tokenId) internal view virtual returns (bool) {
        return totalSupply(tokenId) > 0;
    }
    
    function _mint(
        address account,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) internal virtual override (ERC1155Upgradeable, ERC1155SupplyUpgradeable) {
        super._mint(account, id, amount, data);
    }

    function _mintBatch(
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal virtual override (ERC1155Upgradeable, ERC1155SupplyUpgradeable) {
        super._mintBatch(to, ids, amounts, data);
    }

    function _burn(
        address account,
        uint256 id,
        uint256 amount
    ) internal virtual override (ERC1155Upgradeable, ERC1155SupplyUpgradeable) {
        super._burn(account, id, amount);
    }
    
    function _burnBatch(
        address account,
        uint256[] memory ids,
        uint256[] memory amounts
    ) internal virtual override (ERC1155Upgradeable, ERC1155SupplyUpgradeable) {
        super._burnBatch(account, ids, amounts);
    }

    function _beforeTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal virtual override (ERC1155Upgradeable, ERC1155PausableUpgradeable) {
        super._beforeTokenTransfer(operator, from, to, ids, amounts, data);
    }

    function version() public virtual pure returns (string memory) {
        return "v1";
    }

    uint256[50] private __gap;
}