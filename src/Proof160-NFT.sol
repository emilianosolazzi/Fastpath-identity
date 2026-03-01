// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title Proof160 Early Adopter NFT
 * @notice On-chain SVG NFT collection with dynamic serial numbers.
 */
contract Proof160 is ERC721, Ownable {
    using Strings for uint256;
    using ECDSA for bytes32;

    uint256 public constant MAX_SUPPLY = 160;
    uint256 private _nextTokenId = 1;
    address public trustedSigner;

    mapping(address => bool) public hasClaimed;

    // Events
    event MintedBatch(address indexed to, uint256 startId, uint256 quantity);
    event NFTClaimed(address indexed user, uint256 tokenId);
    event TrustedSignerUpdated(address indexed oldSigner, address indexed newSigner);

    // Custom errors for gas efficiency
    error MaxSupplyReached();
    error MintQuantityInvalid();
    error AlreadyClaimed();
    error InvalidSignature();

    constructor(address _trustedSigner) ERC721("Proof160", "P160") Ownable(msg.sender) {
        trustedSigner = _trustedSigner;
    }

    /**
     * @notice Update the address authorized to sign claim vouchers.
     */
    function setTrustedSigner(address _newSigner) external onlyOwner {
        emit TrustedSignerUpdated(trustedSigner, _newSigner);
        trustedSigner = _newSigner;
    }

    /**
     * @notice Claim the Early Adopter NFT by providing a signature from the trusted signer.
     * @param signature The signature proving testnet participation.
     */
    function claim(bytes calldata signature) external {
        if (hasClaimed[msg.sender]) revert AlreadyClaimed();
        if (_nextTokenId > MAX_SUPPLY) revert MaxSupplyReached();

        bytes32 messageHash = keccak256(abi.encodePacked(msg.sender, block.chainid, "Proof160EarlyAdopter"));
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(messageHash);
        
        address recoveredSigner = ethSignedMessageHash.recover(signature);
        if (recoveredSigner != trustedSigner) revert InvalidSignature();

        hasClaimed[msg.sender] = true;
        uint256 tokenId = _nextTokenId++;
        _safeMint(msg.sender, tokenId);

        emit NFTClaimed(msg.sender, tokenId);
    }

    /**
     * @notice Mints a specific number of tokens to a recipient.
     * @param to The address receiving the NFTs.
     * @param quantity Number of tokens to mint.
     */
    function mintTo(address to, uint256 quantity) external onlyOwner {
        if (quantity == 0) revert MintQuantityInvalid();
        if (_nextTokenId + quantity - 1 > MAX_SUPPLY) revert MaxSupplyReached();

        uint256 startId = _nextTokenId;
        for (uint256 i = 0; i < quantity; ) {
            uint256 tokenId = _nextTokenId++;
            _safeMint(to, tokenId);
            unchecked { i++; }
        }
        emit MintedBatch(to, startId, quantity);
    }

    /**
     * @notice Generates the on-chain SVG image and JSON metadata.
     */
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        _requireOwned(tokenId);

        string memory idStr = tokenId.toString();
        string memory maxStr = MAX_SUPPLY.toString();
        
        // Dynamic SVG Construction (Premium Design)
        bytes memory svg = abi.encodePacked(
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 400">',
            '<defs><linearGradient id="g" x1="0%" y1="0%" x2="100%" y2="100%">',
            '<stop offset="0%" stop-color="#D4AF37"/><stop offset="50%" stop-color="#F2D379"/><stop offset="100%" stop-color="#D4AF37"/></linearGradient></defs>',
            '<circle cx="200" cy="200" r="190" fill="url(#g)"/>',
            '<circle cx="200" cy="200" r="165" fill="#081730"/>',
            '<path d="M200 75 L285 115 V245 L200 290 L115 245 V115 Z" fill="#0c2245" stroke="#00C2A8" stroke-width="1.5" opacity="0.8"/>',
            '<text x="200" y="210" font-family="Arial,sans-serif" font-weight="900" font-size="75" text-anchor="middle" fill="url(#g)">P160</text>',
            '<path d="M90 285 Q200 270 310 285 L310 325 Q200 310 90 325 Z" fill="#00C2A8" />',
            '<text x="200" y="310" font-family="Arial,sans-serif" font-weight="bold" font-size="14" text-anchor="middle" fill="#081730">EARLY ADOPTER</text>',
            '<rect x="135" y="326" width="130" height="26" rx="8" fill="#0c2245" stroke="#00C2A8" stroke-width="1.2" opacity="0.9"/>',
            '<text x="200" y="345" font-family="JetBrains Mono,monospace" font-weight="600" font-size="14" text-anchor="middle" fill="#00C2A8">#', 
            idStr, ' / ', maxStr, '</text></svg>'
        );

        string memory image = string(abi.encodePacked("data:image/svg+xml;base64,", Base64.encode(svg)));

        // Metadata JSON
        bytes memory json = abi.encodePacked(
            '{"name":"Proof160 #', idStr, 
            '","description":"Proof160 Early Adopter Badge. Total supply limited to ', maxStr, '.",',
            '"image":"', image, '",',
            '"attributes":[{"trait_type":"Serial","value":"', idStr, '/', maxStr, 
            '"},{"trait_type":"Tier","value":"Early Adopter"}]}'
        );

        return string(abi.encodePacked("data:application/json;base64,", Base64.encode(json)));
    }

    /**
     * @notice Check if a user is eligible for a discount.
     */
    function hasDiscount(address user) external view returns (bool) {
        return balanceOf(user) > 0;
    }

    /**
     * @notice Returns the current total supply.
     */
    function totalSupply() public view returns (uint256) {
        return _nextTokenId - 1;
    }
}
