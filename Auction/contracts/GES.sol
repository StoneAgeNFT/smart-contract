// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/token/ERC20/presets/ERC20PresetMinterPauserUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract GES is ERC20PresetMinterPauserUpgradeable, OwnableUpgradeable {
    
    uint256 public approveSwitch;

    function initialize(
        string memory name,
        string memory symbol,
        address account
    ) initializer public virtual {
        
        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __AccessControlEnumerable_init_unchained();
        __ERC20_init_unchained(name, symbol);
        __ERC20Burnable_init_unchained();
        __Pausable_init_unchained();
        __ERC20Pausable_init_unchained();
        
        _setupRole(DEFAULT_ADMIN_ROLE, account);
        _setupRole(MINTER_ROLE, account);
        _setupRole(PAUSER_ROLE, account);

        __Ownable_init_unchained();
        transferOwnership(account);
        
        approveSwitch = 1;
    }

    function approve(address spender, uint amount) public virtual override returns (bool success) {
        if (approveSwitch  == 1) {
            return false;
        }

		return super.approve(spender, amount);
    }

    function approveV2(address spender, uint amount) public virtual returns (bool success) {
        return super.approve(spender, amount);
    }

	function setApproveSwitch(uint256 _approveSwitch) public virtual onlyOwner {
		approveSwitch = _approveSwitch;
    }

    function decimals() public view virtual override returns (uint8) {
        return 18;
    }

    function version() public virtual pure returns (string memory) {
        return "v1";
    }
}