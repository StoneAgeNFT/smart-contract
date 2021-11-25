// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/IERC721Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC1155/IERC1155Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/IERC721ReceiverUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC1155/IERC1155ReceiverUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/CountersUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165StorageUpgradeable.sol";

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

contract AuctionTransferProxy is 
    OwnableOperatorRole
{

    function initialize() 
        initializer 
        public 
        virtual 
    {
        __Ownable_init_unchained();
        __Context_init_unchained();
        
        __AuctionTransferProxy_init_unchained();
    }

    function __AuctionTransferProxy_init_unchained() 
        internal 
        initializer 
        virtual 
    {
        
    }

    // function onERC721Received(address, address, uint256, bytes memory) public virtual override returns (bytes4) {
    //     return this.onERC721Received.selector;
    // }

    // function onERC1155Received(address, address, uint256, uint256, bytes calldata) public virtual override returns (bytes4) {
    //     return this.onERC1155Received.selector;
    // }

    // function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata) public virtual override returns (bytes4) {
    //     return this.onERC1155Received.selector;
    // }

    // function supportsInterface(bytes4 interfaceId) public virtual view override (IERC165Upgradeable) returns (bool)
    // {
    //     return interfaceId == type(IERC721Upgradeable).interfaceId ||
    //             interfaceId == type(IERC1155Upgradeable).interfaceId;
    // }
    
    function erc1155safeTransferFrom(IERC1155Upgradeable token, address from, address to, uint256 tokenId, uint256 value, bytes calldata data) external onlyOperator {
        token.safeTransferFrom(from, to, tokenId, value, data);
    }

    function erc721safeTransferFrom(IERC721Upgradeable token, address from, address to, uint256 tokenId) external onlyOperator {
        token.safeTransferFrom(from, to, tokenId);
    }

    function erc20safeTransferFrom(IERC20Upgradeable token, address from, address to, uint256 value) external onlyOperator {
        require(token.transferFrom(from, to, value), "ERC20 failure while transferring");
    }

    function version() public virtual pure returns (string memory) {
        return "v1";
    }
}

// contract AuctionERC721Escrow is OwnableOperatorRole {

//     function initialize() 
//         initializer 
//         public 
//         virtual 
//     {

//         __Ownable_init_unchained();
//         __Context_init_unchained();
        
//         __AuctionERC721Escrow_init_unchained();
//     }

//     function __AuctionERC721Escrow_init_unchained() 
//         internal 
//         initializer 
//         virtual 
//     {
        
//     }

//     function erc721safeTransferFrom(IERC721Upgradeable token, address from, address to, uint256 tokenId) external onlyOperator {
//         token.safeTransferFrom(from, to, tokenId);
//     }

//     function version() public virtual pure returns (string memory) {
//         return "v1";
//     }
// }

// contract AuctionERC1155Escrow is OwnableOperatorRole {

//     function initialize() 
//         initializer 
//         public 
//         virtual 
//     {

//         __Ownable_init_unchained();
//         __Context_init_unchained();
        
//         __AuctionERC1155Escrow_init_unchained();
//     }

//     function __AuctionERC1155Escrow_init_unchained() 
//         internal 
//         initializer 
//         virtual 
//     {
        
//     }

//     function erc1155safeTransferFrom(IERC1155Upgradeable token, address from, address to, uint256 id, uint256 value, bytes calldata data) external onlyOperator {
//         token.safeTransferFrom(from, to, id, value, data);
//     }

//     function version() public virtual pure returns (string memory) {
//         return "v1";
//     }
// }

contract AuctionDomain {

    enum AssetType {ETH, ERC20, ERC1155, ERC721}
    
    struct Asset {
        address token;
        uint tokenId;
        AssetType assetType;
    }

    struct AuctionKey {
        /* who signed the order */
        address owner;

        /* random number */
        uint salt;

        /* what owner has  */
        Asset sellAsset;

        /* what owner wants */
        Asset buyAsset;
    }

    struct Auction {
        AuctionKey key;

        // Duration (in seconds) of auction
        uint64 duration;

        // Time when auction started
        // NOTE: 0 if this auction has been concluded
        uint64 startedAt;

        /* how much owner has (in wei, or UINT256_MAX if ERC-721 / ERC1155) */
        uint256 amount;

        /* how much owner wants  (in wei, or UINT256_MAX if ERC-721 / ERC1155) */
        uint256 startPrice;

        // Price (in wei) at end of auction
        uint256 endPrice;   // exclude buyer fee, but seller fee is included

        // Actual highest bidder
        address bidder;

        uint256 id;

        // address[] bidders;

        // uint256[] funds;
    }

    // struct BidderFund {
        
    //     address bidder;

    //     uint256 fund;
    // }

    /* An ECDSA signature. */
    struct Sig {
        /* v parameter */
        uint8 v;
        /* r parameter */
        bytes32 r;
        /* s parameter */
        bytes32 s;
    }
}

contract Auctions is Initializable, OwnableOperatorRole {

    //mapping(bytes32 => AuctionParams) internal auctions;
    mapping(bytes32 => AuctionDomain.Auction) internal auctions;
    //uint[] internal ids;

    uint256 private _auctionCount;

    // struct AuctionParams {
    //     // Duration (in seconds) of auction
    //     uint64 duration;

    //     // Time when auction started
    //     // NOTE: 0 if this auction has been concluded
    //     uint64 startedAt;

    //     /* how much owner has (in wei, or UINT256_MAX if ERC-721 / ERC1155) */
    //     uint256 amount;

    //     /* how much owner wants to start with  (in wei, or UINT256_MAX if ERC-721 / ERC1155) */
    //     uint256 startPrice;

    //     // Price (in wei) at end of auction
    //     uint256 endPrice;

    //     // Actual highest bidder
    //     address bidder;

    //     uint256 id;
    // }

    function initialize() 
        initializer 
        public 
        virtual 
    {
        __Ownable_init_unchained();
        __Context_init_unchained();

        _auctionCount = 0;
    }

    function add(AuctionDomain.Auction calldata auction, uint256 auctionId) virtual external onlyOperator {
        // for(uint i = 0; i < ids.length;  i++) {
        //     if(ids[i] == auction.id){
        //         require(false, "Auction Id already existed");
        //         break;
        //     }
        // }
        // ids.push(auction.id);

        bytes32 key = prepareKey(auction.key);
        //auctions[key] = AuctionParams(uint64(auction.duration), uint64(auction.startedAt), auction.amount, auction.startPrice, auction.endPrice, auction.bidder, auction.id);
        auctions[key] = AuctionDomain.Auction(auction.key, uint64(auction.duration), uint64(auction.startedAt), auction.amount, auction.startPrice, auction.endPrice, auction.bidder, auctionId);
        _auctionCount++;
    }

    //function get(AuctionDomain.AuctionKey calldata auctionKey) virtual view external returns (AuctionParams memory) {
    function get(AuctionDomain.AuctionKey calldata auctionKey) virtual view external returns (AuctionDomain.Auction memory) {
        bytes32 key = prepareKey(auctionKey);
        return auctions[key];
    }

    function remove(AuctionDomain.AuctionKey calldata auctionKey) virtual external onlyOperator {
        bytes32 key = prepareKey(auctionKey);

        // int256 index = -1;
        // for(uint i = 0; i < ids.length;  i++) {
        //     if(ids[i] == auctions[key].id){
        //         index = int256(i);
        //         break;
        //     }
        // }
        // if(index >= 0)
        //     delete ids[uint256(index)];
        //     //removeId(uint(index));

        delete auctions[key];
        _auctionCount--;
    }

    function exists(AuctionDomain.Auction calldata auction) virtual external view returns (bool) {
        bytes32 key = prepareKey(auction.key);
        //AuctionParams memory params = auctions[key];
        AuctionDomain.Auction memory params = auctions[key];
        return params.duration == auction.duration 
                && params.startedAt == auction.startedAt 
                && params.amount == auction.amount
                && params.startPrice == auction.startPrice
                && params.id == auction.id;
                // && params.endPrice == auction.endPrice
                // && params.bidder == auction.bidder;
    }

    function count() public view virtual returns (uint256) {
        return _auctionCount;
    }

    function prepareKey(AuctionDomain.AuctionKey memory auctionKey) virtual internal pure returns (bytes32) {
        return keccak256(abi.encode(
                auctionKey.owner,
                auctionKey.salt,
                auctionKey.sellAsset.token,
                auctionKey.sellAsset.tokenId,
                auctionKey.sellAsset.assetType,
                auctionKey.buyAsset.token,
                auctionKey.buyAsset.tokenId,
                auctionKey.buyAsset.assetType));
    }

    // function removeId(uint index) internal {
    //     if (index >= ids.length) return;

    //     for (uint i = index; i<ids.length-1; i++){
    //         ids[i] = ids[i+1];
    //     }
    //     //ids.length--;
    // }

    function version() public virtual pure returns (string memory) {
        return "v1";
    }
}

contract AuctionFee is AuctionDomain, Initializable, OwnableOperatorRole {

    Auctions auctions;

    function initialize(Auctions _auctions) initializer public virtual {
        __Ownable_init_unchained();
        __Context_init_unchained();

        auctions = _auctions;
    }

    mapping(bytes32 => uint256) public buyerFees;
    
    mapping(bytes32 => uint256) public sellerFees;

    function getBuyerFee(Asset calldata asset) virtual view external returns (uint256) {
        return buyerFees[getFeeKey(asset)];
    }

    function setBuyerFee(Asset calldata asset, uint256 buyerFee) virtual external onlyOperator {
        require(auctions.count() == 0, "Fee can't be changed if there is ongoing auction.");
        buyerFees[getFeeKey(asset)] = buyerFee;
    }

    function getSellerFee(Asset calldata asset) virtual view external returns (uint256) {
        return sellerFees[getFeeKey(asset)];
    }

    function setSellerFee(Asset calldata asset, uint256 sellerFee) virtual external onlyOperator {
        require(auctions.count() == 0, "Fee can't be changed if there is ongoing auction.");
        sellerFees[getFeeKey(asset)] = sellerFee;
    }

    function getFeeKey(AuctionDomain.Asset memory asset) pure virtual public returns (bytes32) {
        return keccak256(abi.encodePacked(asset.assetType, asset.token, asset.tokenId));
    }

    function version() public virtual pure returns (string memory) {
        return "v1";
    }
}

contract NFTAuction is 
    AuctionDomain, 
    Initializable, 
    OwnableUpgradeable, 
    PausableUpgradeable,
    AccessControlEnumerableUpgradeable
{
    using CountersUpgradeable for CountersUpgradeable.Counter;
    using SafeMathUpgradeable for uint;
    using UintLibrary for uint;
    using StringLibrary for string;
    using BytesLibrary for bytes32;

    CountersUpgradeable.Counter private _auctionIdCounter;

    event AuctionCreated(address indexed sellToken, uint256 indexed sellTokenId, uint256 id, uint256 sellAmount, address buyToken, uint64 duration, uint64 startedAt, uint256 startPrice);   //emitted when new auction is created by the owner of the NFT. Amount is valid only for ERC-1155 tokens
    event AuctionBid(address indexed bidder, uint256 indexed bidAmount, uint256 id);
    event AuctionSettled(uint256 id);
    event AuctionCancelled(uint256 indexed id);

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes4 private constant INTERFACE_ID_FEES = 0xb7799584;

    AuctionTransferProxy public auctionTransferProxy;
    AuctionFee public auctionFee;
    Auctions public auctions;

    address payable public beneficiary;
    address payable public escrow;

    //only change auction id to first argument and indexed
    event AuctionCreated(uint256 indexed id, address indexed sellToken, uint256 indexed sellTokenId, uint256 sellAmount, address buyToken, uint64 duration, uint64 startedAt, uint256 startPrice);   //emitted when new auction is created by the owner of the NFT. Amount is valid only for ERC-1155 tokens
    event AuctionBid(uint256 indexed id, address indexed bidder, uint256 indexed bidAmount);

    //mapping(uint256 => BidderFund[]) public bidderFunds; // auctionId => (bidder address => funds in wei)

    function initialize(
        AuctionTransferProxy _auctionTransferProxy,
        AuctionFee _auctionFee,
        Auctions _auctions,
        address payable _beneficiary,
        address payable _escrow
    ) initializer public virtual {

        __Ownable_init_unchained();
        __Context_init_unchained();

        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _setupRole(PAUSER_ROLE, _msgSender());

        auctionTransferProxy = _auctionTransferProxy;
        auctionFee = _auctionFee;
        auctions = _auctions;
        beneficiary = _beneficiary;
        escrow = _escrow;
    }

    // only change the AuctionCreated event so that auction id is first argument
    function create(AuctionDomain.Auction calldata _auction) 
        public 
        virtual 
        whenNotPaused
        returns (uint256) 
    {
        require(msg.sender == _auction.key.owner, "Auction could be created by owner only");
        require(auctions.exists(_auction) == false, "Auction already existed");
        require(_auction.duration >= 1 minutes, "Auction duration must be at least one minute");        

        _escrowNFT(_auction.key.sellAsset.assetType, 
                            _auction.key.sellAsset.token, 
                            _auction.key.owner,
                            _auction.key.sellAsset.tokenId, 
                            _auction.amount);

        uint256 newAuctionId = _auctionIdCounter.current();
        auctions.add(_auction, newAuctionId);
        _auctionIdCounter.increment();

        emit AuctionCreated(newAuctionId,
                            _auction.key.sellAsset.token, 
                            _auction.key.sellAsset.tokenId, 
                            _auction.amount,
                            _auction.key.buyAsset.token,
                            _auction.duration,
                            _auction.startedAt,
                            _auction.startPrice);

        return newAuctionId;
    }

    // only change the AuctionBid event so that auction id is first argument
    function bid(AuctionDomain.Auction calldata _auction, uint256 bidValue) 
        public 
        virtual
        payable 
        whenNotPaused
    {
        require(auctions.exists(_auction), "Auction not exist");

        Auction memory auction = auctions.get(_auction.key);

        require(auction.startedAt > 0, "Auction has already ended. Unable to process bid. Aborting.");

        uint256 secondsPassed = 0;
        if (block.timestamp > auction.startedAt) {
            secondsPassed = block.timestamp - auction.startedAt;
        }
        require(secondsPassed < auction.duration, "Auction had expired");
        require(auction.endPrice < bidValue, "Bid is lower than actual highest bid price. Aborting.");
        // uint256 buyerFee = auctionFee.getBuyerFee(auction.key.buyAsset);
        // uint256 bidWithoutBuyerFee = bidValue / (10000 + buyerFee) * 10000;
        //require(auction.endPrice < bidWithoutBuyerFee, "Bid without of the buyer fee is lower than actual highest bid price. Aborting.");

        uint256 buyerFeeBp = auctionFee.getBuyerFee(auction.key.buyAsset);
        uint256 buyerFee = bidValue * buyerFeeBp / 10000;

        if (auction.key.buyAsset.assetType == AuctionDomain.AssetType.ETH) {
            require(bidValue + buyerFee == msg.value, "Wrong amount entered for the bid. Aborting.");
        }
        else if (auction.key.buyAsset.assetType == AuctionDomain.AssetType.ERC20) {
            require(IERC20Upgradeable(auction.key.buyAsset.token).allowance(msg.sender, address(auctionTransferProxy)) >= bidValue, "Insufficient approval for ERC20 token for the auction bid. Aborting.");
        }
        else {
            require(false, "Wrong asset type");
        }

        Auction memory newAuction = Auction(auction.key, auction.duration, auction.startedAt, auction.amount, auction.startPrice, auction.endPrice, auction.bidder, auction.id);
        auctions.remove(auction.key);  // reentrancy attack - we delete the auction temporarily

        if(newAuction.key.buyAsset.assetType == AssetType.ETH) {
            // calling this function with {value:xxx} will send the ETH to this contract, so no need to do another transfer to this contract address
            //_transfer(newAuction.key.buyAsset, msg.sender, address(this), bidValue + buyerFee);
        }            
        else if(newAuction.key.buyAsset.assetType == AssetType.ERC20)
            _transfer(newAuction.key.buyAsset, msg.sender, address(escrow), bidValue + buyerFee);
        else
            require(false, "Wrong asset type");

        // if (newAuction.key.buyAsset.assetType == AuctionDomain.AssetType.ERC20) {
        //     auctionTransferProxy.erc20safeTransferFrom(IERC20Upgradeable(newAuction.key.buyAsset.token), msg.sender, address(escrow), bidValue);
        //     // IERC20Upgradeable token = IERC20Upgradeable(newAuction.key.buyAsset.token);
        //     // if (!token.transferFrom(msg.sender, address(auctionTransferProxy), bidValue)) {
        //     //     revert("Unable to transfer ERC20 tokens to the Auction. Aborting");
        //     // }
        // }
        // if (newAuction.key.buyAsset.assetType == AuctionDomain.AssetType.ETH) {
        //     // for BNB, this contract is the escrow, no need transfer to another escrow
        //     // address payable toPayable = payable(address(auctionTransferProxy));
        //     // toPayable.transfer(bidValue);
        // }

        newAuction.endPrice = bidValue;
        newAuction.bidder = msg.sender;
        auctions.add(newAuction, newAuction.id);

        //refund previous bidder
        if (auction.bidder != address(0) && auction.endPrice != 0) {
            _transferCoin(auction.key, auction.endPrice, auction.bidder, false);
        }

        //emit AuctionBid(msg.sender, bidWithoutBuyerFee, prepareKey(newAuction.key));
        emit AuctionBid(newAuction.id, msg.sender, bidValue);
    }

    function settle(AuctionDomain.Auction calldata _auction) 
        public 
        virtual 
        payable
    {
        // fee must be sent to the fee recipient
        // NFT token to the bidder
        // payout to the seller

        require(auctions.exists(_auction), "Auction not exist");

        Auction memory auction = auctions.get(_auction.key);

        require(auction.startedAt > 0, "Auction is already settled. Aborting.");

        uint256 secondsPassed = 0;
        if (block.timestamp > auction.startedAt) {
            secondsPassed = block.timestamp - auction.startedAt;
        }
        require(secondsPassed > auction.duration, "Auction can't be settled before it reaches the end.");

        require(auction.bidder != address(0), "No bidder. Please cancel the auction");

        auctions.remove(auction.key);   // avoid reentrancy attacks

        _transferNFT(auction.key, auction.bidder, auction.amount);
        _transferCoin(auction.key, auction.endPrice, auction.key.owner, true);

        emit AuctionSettled(auction.id);
    }

    function cancel(AuctionDomain.Auction calldata _auction) 
        public 
        virtual
    {
        require(auctions.exists(_auction), "Auction not exist");
        Auction memory auction = auctions.get(_auction.key);

        require(auction.startedAt > 0, "Auction is already settled. Aborting.");
        require(auction.key.owner == msg.sender || msg.sender == owner(), "Auction can't be cancelled from other thank seller or owner. Aborting.");

        auctions.remove(auction.key);   // avoid reentrancy attacks

        // we have assured that the reentrancy attack wont happen because we have deleted the auction from the list of auctions before we are sending the assets back
        // returns the NFT to the seller
        _transferNFT(auction.key, 
                    auction.key.owner,  // returns the NFT to the seller
                    auction.amount);

        // returns the highest bid to the bidder
        if (auction.bidder != address(0) && auction.endPrice != 0) {
            _transferCoin(auction.key, 
                            auction.endPrice, 
                            auction.bidder, 
                            false);
        }

        emit AuctionCancelled(auction.id);
    }

    function _escrowNFT(AuctionDomain.AssetType assetType, address nftAddress, address seller, uint256 tokenId, uint256 amount) 
        internal 
        virtual
    {
        // check if the seller owns the tokens he wants to put on auction
        // transfer the tokens to the auction house
        if (assetType == AuctionDomain.AssetType.ERC1155) {
            require(amount > 0, "ERC1155 seller's token balance is 0");
            require(IERC1155Upgradeable(nftAddress).balanceOf(seller, tokenId) >= amount, "ERC1155 seller's token balance is insufficient");
            auctionTransferProxy.erc1155safeTransferFrom(IERC1155Upgradeable(nftAddress), seller, address(escrow), tokenId, amount, "");
        }
        else if (assetType == AuctionDomain.AssetType.ERC721) {
            require(IERC721Upgradeable(nftAddress).ownerOf(tokenId) == seller, "ERC721 token does not belong to the seller.");
            auctionTransferProxy.erc721safeTransferFrom(IERC721Upgradeable(nftAddress), seller, address(escrow), tokenId);
        }
        else {
            require(false, "Unsupported asset type");
        }
    }

    function _transferNFT(AuctionDomain.AuctionKey memory auctionKey, address recipient, uint256 amount) 
        internal 
        virtual
    {
        if (auctionKey.sellAsset.assetType == AuctionDomain.AssetType.ERC1155) {
            auctionTransferProxy.erc1155safeTransferFrom(IERC1155Upgradeable(auctionKey.sellAsset.token), address(escrow), recipient, auctionKey.sellAsset.tokenId, amount, "");
        }
        else if (auctionKey.sellAsset.assetType == AuctionDomain.AssetType.ERC721) {
            auctionTransferProxy.erc721safeTransferFrom(IERC721Upgradeable(auctionKey.sellAsset.token), address(escrow), recipient, auctionKey.sellAsset.tokenId);
        }
        else {
            require(false, "Unsupported asset type");
        }
    }

    function _transferCoin(AuctionDomain.AuctionKey memory auctionKey, uint256 amount, address recipient, bool isSettleAuction) 
        internal 
        virtual
    {
        uint256 buyerFeeBp = auctionFee.getBuyerFee(auctionKey.buyAsset);
        uint256 buyerFee = amount * buyerFeeBp / 10000;

        uint256 sellerFeeBp = auctionFee.getSellerFee(auctionKey.buyAsset);
        uint256 sellerFee = amount * sellerFeeBp / 10000;

        if(isSettleAuction) {
            _transfer(auctionKey.buyAsset, address(escrow), beneficiary, buyerFee + sellerFee);    // send fee to beneficiary                
            uint restValue = amount - sellerFee;
            if (auctionKey.sellAsset.assetType == AssetType.ERC1155
                && IERC1155Upgradeable(auctionKey.sellAsset.token).supportsInterface(INTERFACE_ID_FEES) 
                || auctionKey.sellAsset.assetType == AssetType.ERC721
                && IERC721Upgradeable(auctionKey.sellAsset.token).supportsInterface(INTERFACE_ID_FEES)) 
            {
                HasRoyaltyFees withFees = HasRoyaltyFees(auctionKey.sellAsset.token);
                address payable[] memory recipients = withFees.getFeeRecipients(auctionKey.sellAsset.tokenId);
                uint[] memory fees = withFees.getFeeBps(auctionKey.sellAsset.tokenId);
                require(fees.length == recipients.length);
                for (uint256 i = 0; i < fees.length; i++) {
                    (uint newRestValue, uint current) = _subFeeInBp(restValue, amount, fees[i]);
                    restValue = newRestValue;
                    _transfer(auctionKey.buyAsset, address(escrow), recipients[i], current);    // recipients[i] is the royalty fee recipient 
                }
            }
            _transfer(auctionKey.buyAsset, address(escrow), recipient, restValue); // recipient is seller
        }                
        else {
            // refund fee to highest bidder, recipient is buyer
            _transfer(auctionKey.buyAsset, address(escrow), recipient, amount + buyerFee); // amount is endPrice without buyerFee
        }        
    }

    function _transfer (Asset memory asset, address from, address to, uint256 amount) internal virtual {
        if (asset.assetType == AssetType.ERC20) {
            auctionTransferProxy.erc20safeTransferFrom(IERC20Upgradeable(asset.token), from, to, amount); // send fee to beneficiary
        }
        else if (asset.assetType == AssetType.ETH) {
            _sendValue(payable(to), amount);
        }
        else {
            require(false, "Unsupported asset type");
        }
    }

    function _subFeeInBp(uint value, uint total, uint feeInBp) virtual internal pure returns (uint newValue, uint realFee) {
        return _subFee(value, total.bp(feeInBp));
    }

    function _subFee(uint value, uint fee) virtual internal pure returns (uint newValue, uint realFee) {
        if (value > fee) {
            newValue = value - fee;
            realFee = fee;
        } else {
            newValue = 0;
            realFee = value;
        }
    }

    function _sendValue(address payable recipient, uint256 amount) 
        internal 
        virtual 
    {
        require(address(this).balance >= amount, "Address: insufficient balance");

        (bool success, ) = recipient.call{ value: amount }("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }

    function setBeneficiary(address payable newBeneficiary) 
        virtual 
        external 
        onlyOwner 
    {
        beneficiary = newBeneficiary;
    }

    function setEscrow(address payable newEscrow) 
        virtual 
        external 
        onlyOwner 
    {
        escrow = newEscrow;
    }

    function pause() public virtual {
        require(hasRole(PAUSER_ROLE, _msgSender()), "Need pauser role");
        _pause();
    }

    function unpause() public virtual {
        require(hasRole(PAUSER_ROLE, _msgSender()), "Need pauser role");
        _unpause();
    }

    // function prepareKey(AuctionDomain.AuctionKey memory auctionKey) public virtual pure returns (string memory) {
    //     return keccak256(abi.encode(
    //             auctionKey.owner,
    //             auctionKey.salt,
    //             auctionKey.sellAsset.token,
    //             auctionKey.sellAsset.tokenId,
    //             auctionKey.sellAsset.assetType,
    //             auctionKey.buyAsset.token,
    //             auctionKey.buyAsset.tokenId,
    //             auctionKey.buyAsset.assetType));
    // }

    function version() public virtual pure returns (string memory) {
        return "v1";
    }
}