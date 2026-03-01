// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title FastPath BTC Primitives
 * @author Emiliano Solazzi 2025
 * @notice Lossless Bitcoin address translation library for EVM.
 */

library FastPathBTC {
    // Custom errors for gas-efficient reverts
    error InvalidBase58Char();
    error InvalidPackedAddress();
    error CorruptedPackedData();
    error InvalidAddressLength();
    error InvalidBech32HrpLength();
    error InvalidAddressType();
    error InvalidChecksum();
    error InvalidBase58Checksum();
    error InvalidBech32Checksum();
    error SliceOutOfBounds();
    error InvalidBech32Char();

    // Length and protocol constants
    uint8 constant internal MIN_ADDR_LEN = 26;
    uint8 constant internal MAX_ADDR_LEN = 62;
    uint8 constant internal MIN_BASE58_LEN = 26;
    uint8 constant internal MAX_BASE58_LEN = 35;
    uint8 constant internal BASE58_DECODE_MIN = 25; // 21 hash + 4 checksum
    uint8 constant internal BASE58_HASH_LEN = 21;
    uint8 constant internal BASE58_CHECKSUM_LEN = 4;
    uint8 constant internal MIN_BECH32_SEP_REMAIN = 7; // min chars after separator (1+6 checksum)

    // Bech32 polymod targets
    uint32 constant internal BECH32_CONST = 1;
    uint32 constant internal BECH32M_CONST = 0x2bc830a3;

    // Base58 alphabet for encoding/decoding
     bytes constant internal ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

     // Bech32 alphabet
     bytes constant internal BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    
    // Bech32 generator polynomials
    uint32 constant internal GEN0 = 0x3b6a57b2;
    uint32 constant internal GEN1 = 0x26508e6d;
    uint32 constant internal GEN2 = 0x1ea119fa;
    uint32 constant internal GEN3 = 0x3d4233dd;
    uint32 constant internal GEN4 = 0x2a1462b3;
    // Packed address integrity magic (first two bytes of keccak prefix)
    bytes2 constant internal PACKED_MAGIC = 0xF3A7;
    
    // Bitcoin address type identifiers
    enum AddressType {
        P2PKH,      // 1...
        P2SH,       // 3...
        BECH32,     // bc1...
        BECH32M,    // bc1... (Taproot)
        UNKNOWN
    }
    
    // Packed address struct for efficient storage
    /**
     * @dev PackedAddress layout (lossless):
     * - `part1` : First 32 bytes of the address string (left-aligned).
     * - `part2` : Next 32 bytes (only used when length > 32).
     * - `len`   : Original address length in bytes (26..62).
     * - `addrType` : Detected AddressType enum value.
     *
     * Note:
     * - This layout is not an on-chain standard; callers must enforce `len` and `addrType` bounds.
     * - The `part2` field is zero-padded if the address length is less than or equal to 32 bytes.
     */
    struct PackedAddress {
        bytes32 part1; // First 32 bytes
        bytes32 part2; // Next 30 bytes (max 62 total)
        uint8 len;     // Store the original length
        AddressType addrType; // Address type for validation
    }
    
    // ===== Address Round-Trip =====
    
    /**
     * @notice Pack a Bitcoin address string into a PackedAddress
     * @param addr Bitcoin address as string (26-62 chars)
     * @return packed PackedAddress struct
     */
    function packAddress(bytes memory addr) internal pure returns (PackedAddress memory packed) {
    /**
     * @dev Pack a bytes address into `PackedAddress` without performing integrity checks.
     * The integrity keccak prefix is computed on `unpackAddress` to avoid
     * redundant work during packing and to keep pack cheap for on-path usage.
     */
        uint256 len = addr.length;
        if (len < MIN_ADDR_LEN || len > MAX_ADDR_LEN) revert InvalidAddressLength();

        // Determine address type
        AddressType addrType = detectAddressType(addr);

        // Pack into bytes32 slots
        bytes32 p1;
        bytes32 p2;

        // Copy first and second 32-byte words directly (second may contain padding)
        assembly {
            p1 := mload(add(addr, 32))
            p2 := mload(add(addr, 64))
        }
        // If address fits in first word, clear p2 to avoid leaking memory
        if (len <= 32) {
            p2 = bytes32(0);
        }

        return PackedAddress(p1, p2, uint8(len), addrType);
    }
    
    /**
     * @notice Unpack a PackedAddress back to the original Bitcoin address string
     * @param packed PackedAddress struct
     * @return addr Original Bitcoin address
     */
    function unpackAddress(PackedAddress memory packed) internal pure returns (bytes memory addr) {
        uint8 len = packed.len;
        // Validate packed struct fields to prevent malformed data (M-01)
        uint8 at = uint8(packed.addrType);
        if (at > uint8(AddressType.UNKNOWN)) revert InvalidPackedAddress();
        AddressType addrType = packed.addrType; // Cache addrType in memory
        if (addrType == AddressType.UNKNOWN) revert InvalidPackedAddress();
        if (len < MIN_ADDR_LEN || len > MAX_ADDR_LEN) revert InvalidAddressLength();

        // Integrity verification to detect corrupted or maliciously crafted packed data (M-01)
        // Compute a keccak over the canonical packed fields and compare the first
        // two bytes to `PACKED_MAGIC` to detect tampering.
        bytes32 _computed = keccak256(bytes.concat(packed.part1, packed.part2, bytes1(packed.len), bytes1(uint8(packed.addrType))));
        if (bytes2(_computed) != PACKED_MAGIC) revert CorruptedPackedData();

        addr = new bytes(len);

        // Copy part1 and part2 only as needed
        bytes32 p1 = packed.part1;
        bytes32 p2 = packed.part2;
        assembly {
            mstore(add(addr, 32), p1)
        }
        if (len > 32) {
            assembly {
                mstore(add(addr, 64), p2)
            }
        }
    }
    
    // ===== Address Validation =====
    
    /**
     * @notice Validate a Bitcoin address with optional strict validation
     * @param addr Bitcoin address string
     * @param strict If true, perform full validation (checksum, format)
     * @return isValid True if address is valid
     */
    function validateAddress(string memory addr, bool strict) internal pure returns (bool isValid) {
        bytes memory data = bytes(addr);
        uint256 dlen = data.length;
        if (dlen > 100) revert InvalidAddressLength(); // Maximum length check
        if (dlen < MIN_ADDR_LEN || dlen > MAX_ADDR_LEN) {
            if (strict) revert InvalidAddressLength();
            return false;
        }

        AddressType addrType = detectAddressType(data);

        if (!strict) {
            return addrType != AddressType.UNKNOWN;
        }

        // Strict validation based on address type. On strict mode revert with structured errors.
        if (addrType == AddressType.P2PKH || addrType == AddressType.P2SH) {
            bool ok = validateBase58Address(data);
            if (!ok) revert InvalidBase58Checksum();
            return true;
        } else if (addrType == AddressType.BECH32 || addrType == AddressType.BECH32M) {
            bool ok = validateBech32Address(data, addrType == AddressType.BECH32M, strict, strict);
            if (!ok) revert InvalidBech32Checksum();
            return true;
        }

        revert InvalidAddressType();
    }
    
    /**
     * @notice Detect Bitcoin address type from bytes
     * @param data Address bytes
     * @return addrType Detected address type
     */
    function detectAddressType(bytes memory data) internal pure returns (AddressType addrType) {
        return detectAddressTypeInternal(data);
    }
    
    // ===== Base58 Validation =====
    
    /**
     * @notice Validate Base58 encoded address (P2PKH/P2SH)
     * @param data Address bytes
     * @return isValid True if valid Base58 address
     */
    function validateBase58Address(bytes memory data) internal pure returns (bool isValid) {
        // Basic length check
        if (data.length < MIN_BASE58_LEN || data.length > MAX_BASE58_LEN) return false;

        // Decode Base58
        bytes memory decoded = base58Decode(data);
        uint256 dlen = decoded.length;
        if (dlen < BASE58_DECODE_MIN) return false; // 21 byte hash + 4 byte checksum

        // Verify checksum (double SHA256 of first BASE58_HASH_LEN bytes)
        bytes memory first21 = sliceBytes(decoded, 0, BASE58_HASH_LEN);
        bytes32 h1 = sha256Hash(first21);
        bytes32 h2 = sha256Hash(bytes.concat(h1));
        bytes memory h2b = bytes.concat(h2);

        // Compare last BASE58_CHECKSUM_LEN bytes
        for (uint256 i = 0; i < BASE58_CHECKSUM_LEN; i++) {
            if (decoded[dlen - BASE58_CHECKSUM_LEN + i] != h2b[i]) {
                return false;
            }
        }

        return true;
    }
    
    /**
     * @notice Base58 decode implementation
     * @param data Base58 encoded data
     * @return decoded Decoded bytes
     */
    function base58Decode(bytes memory data) internal pure returns (bytes memory decoded) {
        uint256[] memory digits = new uint256[](data.length);
        
        // Convert characters to digits
        for (uint256 i = 0; i < data.length; i++) {
            digits[i] = base58CharToValue(data[i]);
            if (digits[i] == 255) {
                revert InvalidBase58Char();
            }
        }
        
        // Convert from base58
        uint256[] memory decodedArray = new uint256[](data.length * 733 / 1000 + 1); // log(58)/log(256)
        uint256 decodedLength = 1;
        
        for (uint256 i = 0; i < digits.length; i++) {
            uint256 carry = digits[i];
            for (uint256 j = 0; j < decodedArray.length; j++) {
                carry += decodedArray[j] * 58;
                decodedArray[j] = carry % 256;
                carry = carry / 256;
            }
            
            while (carry > 0) {
                decodedArray[decodedLength++] = carry % 256;
                carry = carry / 256;
            }
        }
        
        // Remove leading zeros
        uint256 leadingZeros;
        for (leadingZeros = 0; leadingZeros < data.length && data[leadingZeros] == ALPHABET[0]; leadingZeros++) {}
        
        decoded = new bytes(decodedLength + leadingZeros);
        for (uint256 i = 0; i < leadingZeros; i++) {
            decoded[i] = 0;
        }
        
        for (uint256 i = 0; i < decodedLength; i++) {
            decoded[leadingZeros + i] = bytes1(uint8(decodedArray[decodedLength - 1 - i]));
        }
    }
    
    function base58CharToValue(bytes1 c) internal pure returns (uint256 value) {
        // Explicit mapping for Base58 characters to values. Implemented as
        // comparisons to avoid dynamic loops and to be gas-friendlier than
        // iterating over `ALPHABET` in hot paths.
        bytes1 b = c;
        if (b == 0x31) return 0; // '1'
        if (b == 0x32) return 1; // '2'
        if (b == 0x33) return 2; // '3'
        if (b == 0x34) return 3; // '4'
        if (b == 0x35) return 4; // '5'
        if (b == 0x36) return 5; // '6'
        if (b == 0x37) return 6; // '7'
        if (b == 0x38) return 7; // '8'
        if (b == 0x39) return 8; // '9'
        if (b == 0x41) return 9; // 'A'
        if (b == 0x42) return 10; // 'B'
        if (b == 0x43) return 11; // 'C'
        if (b == 0x44) return 12; // 'D'
        if (b == 0x45) return 13; // 'E'
        if (b == 0x46) return 14; // 'F'
        if (b == 0x47) return 15; // 'G'
        if (b == 0x48) return 16; // 'H'
        if (b == 0x4A) return 17; // 'J'
        if (b == 0x4B) return 18; // 'K'
        if (b == 0x4C) return 19; // 'L'
        if (b == 0x4D) return 20; // 'M'
        if (b == 0x4E) return 21; // 'N'
        if (b == 0x4F) return 22; // 'O' (excluded in Bitcoin Base58 normally)
        if (b == 0x50) return 23; // 'P'
        if (b == 0x51) return 24; // 'Q'
        if (b == 0x52) return 25; // 'R'
        if (b == 0x53) return 26; // 'S'
        if (b == 0x54) return 27; // 'T'
        if (b == 0x55) return 28; // 'U'
        if (b == 0x56) return 29; // 'V'
        if (b == 0x57) return 30; // 'W'
        if (b == 0x58) return 31; // 'X'
        if (b == 0x59) return 32; // 'Y'
        if (b == 0x5A) return 33; // 'Z'
        if (b == 0x61) return 34; // 'a'
        if (b == 0x62) return 35; // 'b'
        if (b == 0x63) return 36; // 'c'
        if (b == 0x64) return 37; // 'd'
        if (b == 0x65) return 38; // 'e'
        if (b == 0x66) return 39; // 'f'
        if (b == 0x67) return 40; // 'g'
        if (b == 0x68) return 41; // 'h'
        if (b == 0x69) return 42; // 'i' (excluded in Bitcoin Base58)
        if (b == 0x6A) return 43; // 'j'
        if (b == 0x6B) return 44; // 'k'
        if (b == 0x6C) return 45; // 'l'
        if (b == 0x6D) return 46; // 'm'
        if (b == 0x6E) return 47; // 'n'
        if (b == 0x6F) return 48; // 'o' (excluded)
        if (b == 0x70) return 49; // 'p'
        if (b == 0x71) return 50; // 'q'
        if (b == 0x72) return 51; // 'r'
        if (b == 0x73) return 52; // 's'
        if (b == 0x74) return 53; // 't'
        if (b == 0x75) return 54; // 'u'
        if (b == 0x76) return 55; // 'v'
        if (b == 0x77) return 56; // 'w'
        if (b == 0x78) return 57; // 'x'
        if (b == 0x79) return 58; // 'y'
        if (b == 0x7A) return 59; // 'z'
        return 255;
    }
    
    // ===== Bech32 Validation =====
    
    /**
     * @notice Validate Bech32/Bech32m address
     * @param data Address bytes
     * @param isBech32m True for Bech32m, false for Bech32
     * @return isValid True if valid
     */
    function validateBech32Address(bytes memory data, bool isBech32m, bool requireMainnet, bool revertOnError) internal pure returns (bool isValid) {
        // Find separator '1'
        uint256 sepPos = 0;
        uint256 dlen = data.length;
        for (uint256 i = 0; i < dlen; i++) {
            if (data[i] == bytes1(0x31)) { // '1'
                sepPos = i;
                break;
            }
        }
        // Reject mixed-case per BIP-173: address must be all-lowercase or all-uppercase
        bool hasLower = false;
        bool hasUpper = false;
        uint256 total = dlen;
        for (uint256 i = 0; i < total; i++) {
            bytes1 ch = data[i];
            if (ch >= 0x61 && ch <= 0x7a) hasLower = true; // 'a'..'z'
            if (ch >= 0x41 && ch <= 0x5a) hasUpper = true; // 'A'..'Z'
            if (hasLower && hasUpper) return false;
        }
        // HRP length must be at least 1 and at most 83 per BIP-173
        if (sepPos == 0 || sepPos > dlen - MIN_BECH32_SEP_REMAIN) {
            if (revertOnError) revert InvalidBech32HrpLength();
            return false;
        }
        uint256 hrpLen = sepPos;
        if (hrpLen < 1 || hrpLen > 83) {
            if (revertOnError) revert InvalidBech32HrpLength();
            return false;
        }

        // HRP (human-readable part)
        bytes memory hrp = new bytes(hrpLen);
        for (uint256 i = 0; i < hrpLen; i++) {
            hrp[i] = data[i];
        }

        // If caller requires mainnet enforcement, ensure HRP == "bc"
        if (requireMainnet) {
            if (!(hrpLen == 2 && hrp[0] == 0x62 && hrp[1] == 0x63)) {
                if (revertOnError) revert InvalidBech32HrpLength();
                return false;
            }
        }
        
        // Data part (after separator)
        uint256 dpLen = dlen - hrpLen - 1;
        bytes memory dataPart = new bytes(dpLen);
        for (uint256 i = 0; i < dpLen; i++) {
            dataPart[i] = data[hrpLen + 1 + i];
        }

        // Convert to 5-bit values
        uint8[] memory values = new uint8[](dpLen);
        for (uint256 i = 0; i < dpLen; i++) {
            values[i] = charToBech32Value(dataPart[i]);
            if (values[i] == 255) return false;
        }

        // Verify checksum
        return verifyChecksum(hrp, values, isBech32m);
    }
    
    /**
     * @notice Verify Bech32/Bech32m checksum
     * @param hrp Human-readable part
     * @param values 5-bit values
     * @param isBech32m True for Bech32m
     * @return isValid True if checksum valid
     */
    function verifyChecksum(bytes memory hrp, uint8[] memory values, bool isBech32m) internal pure returns (bool isValid) {
        // Expand HRP
        uint8[] memory expanded = expandHrp(hrp);
        
        // Combine with values
        uint8[] memory combined = new uint8[](expanded.length + values.length);
        for (uint256 i = 0; i < expanded.length; i++) {
            combined[i] = expanded[i];
        }
        for (uint256 i = 0; i < values.length; i++) {
            combined[expanded.length + i] = values[i];
        }
        
        // Calculate polymod and compare to target constant
        uint32 target = isBech32m ? BECH32M_CONST : BECH32_CONST;
        uint32 v = polymod(combined);

        return v == target;
    }
    
    /**
     * @notice Expand HRP for checksum calculation
     * @param hrp Human-readable part
     * @return expanded Expanded bytes
     */
    function expandHrp(bytes memory hrp) internal pure returns (uint8[] memory expanded) {
        expanded = new uint8[](hrp.length * 2 + 1);
        
        for (uint256 i = 0; i < hrp.length; i++) {
            expanded[i] = uint8(hrp[i]) >> 5;
            expanded[hrp.length + 1 + i] = uint8(hrp[i]) & 31;
        }
        expanded[hrp.length] = 0; // Separator
    }
    
    /**
     * @notice Bech32 polymod function
     * @param values 5-bit values
     * @return checksum Calculated checksum
     */
    function polymod(uint8[] memory values) internal pure returns (uint32 checksum) {
        if (values.length == 0) revert InvalidChecksum();
        uint32 chk = 1;
        uint256 len = values.length;
        for (uint256 i = 0; i < len - 6; i++) {
            if (values[i] >= 32) revert InvalidBech32Char(); // Ensure 5-bit values
            uint32 b = chk >> 25;
            chk = (chk & 0x1ffffff) << 5 ^ uint32(values[i]);
            if (b & 1 != 0) chk ^= GEN0;
            if (b & 2 != 0) chk ^= GEN1;
            if (b & 4 != 0) chk ^= GEN2;
            if (b & 8 != 0) chk ^= GEN3;
            if (b & 16 != 0) chk ^= GEN4;
        }
        // Unroll last 6 iterations
        for (uint256 i = len - 6; i < len; i++) {
            if (values[i] >= 32) revert InvalidBech32Char();
            uint32 b = chk >> 25;
            chk = (chk & 0x1ffffff) << 5 ^ uint32(values[i]);
            if (b & 1 != 0) chk ^= GEN0;
            if (b & 2 != 0) chk ^= GEN1;
            if (b & 4 != 0) chk ^= GEN2;
            if (b & 8 != 0) chk ^= GEN3;
            if (b & 16 != 0) chk ^= GEN4;
        }
        return chk;
    }
    
    // Full Bech32 character mapping for validation
    function charToBech32Value(bytes1 c) internal pure returns (uint8) {
        // Accept lowercase or uppercase letters, but caller enforces no mixed-case
        // Map both cases to the same 5-bit value
        if (c == 0x71 || c == 0x51) return 0; // q Q
        if (c == 0x70 || c == 0x50) return 1; // p P
        if (c == 0x7a || c == 0x5a) return 2; // z Z
        if (c == 0x72 || c == 0x52) return 3; // r R
        if (c == 0x79 || c == 0x59) return 4; // y Y
        if (c == 0x39) return 5; // 9
        if (c == 0x78 || c == 0x58) return 6; // x X
        if (c == 0x38) return 7; // 8
        if (c == 0x67 || c == 0x47) return 8; // g G
        if (c == 0x66 || c == 0x46) return 9; // f F
        if (c == 0x32) return 10; // 2
        if (c == 0x74 || c == 0x54) return 11; // t T
        if (c == 0x76 || c == 0x56) return 12; // v V
        if (c == 0x64 || c == 0x44) return 13; // d D
        if (c == 0x77 || c == 0x57) return 14; // w W
        if (c == 0x30) return 15; // 0
        if (c == 0x73 || c == 0x53) return 16; // s S
        if (c == 0x33) return 17; // 3
        if (c == 0x6a || c == 0x4a) return 18; // j J
        if (c == 0x6e || c == 0x4e) return 19; // n N
        if (c == 0x35) return 20; // 5
        if (c == 0x34) return 21; // 4
        if (c == 0x6b || c == 0x4b) return 22; // k K
        if (c == 0x68 || c == 0x48) return 23; // h H
        if (c == 0x63 || c == 0x43) return 24; // c C
        if (c == 0x65 || c == 0x45) return 25; // e E
        if (c == 0x36) return 26; // 6
        if (c == 0x6d || c == 0x4d) return 27; // m M
        if (c == 0x75 || c == 0x55) return 28; // u U
        if (c == 0x61 || c == 0x41) return 29; // a A
        if (c == 0x37) return 30; // 7
        if (c == 0x6c || c == 0x4c) return 31; // l L
        return 255; // Invalid
    }
    
    // ===== Helper Functions =====
    
    // toETHHex removed: this placeholder provided no functionality and
    // has been intentionally removed to avoid dead code. If conversion
    // from Bitcoin address to Ethereum-style hex is needed, implement
    // a standalone utility that clearly documents expected semantics.
    
    /**
     * @notice Get address type as string
     * @param addrType Address type enum
     * @return typeString Human-readable type
     */
    function getAddressTypeString(AddressType addrType) internal pure returns (string memory typeString) {
        if (addrType == AddressType.P2PKH) return "P2PKH";
        if (addrType == AddressType.P2SH) return "P2SH";
        if (addrType == AddressType.BECH32) return "Bech32";
        if (addrType == AddressType.BECH32M) return "Bech32m";
        return "UNKNOWN";
    }
    
    // ===== Helpers =====

    function sliceBytes(bytes memory data_, uint256 start_, uint256 len_) internal pure returns (bytes memory) {
        if (start_ + len_ > data_.length) revert SliceOutOfBounds();
        bytes memory ret = new bytes(len_);
        if (len_ == 0) return ret;

        // Use efficient memory copy in assembly: copy full 32-byte words,
        // then copy the remaining tail bytes in a safe Solidity loop.
        uint256 words = len_ / 32;
        uint256 rem = len_ - words * 32;
        assembly {
            let src := add(add(data_, 32), start_)
            let dst := add(ret, 32)
            for { let i := 0 } lt(i, words) { i := add(i, 1) } {
                mstore(dst, mload(src))
                dst := add(dst, 32)
                src := add(src, 32)
            }
        }
        if (rem > 0) {
            uint256 srcIndex = start_ + words * 32;
            uint256 dstIndex = words * 32;
            for (uint256 i = 0; i < rem; i++) {
                ret[dstIndex + i] = data_[srcIndex + i];
            }
        }
        return ret;
    }

    // ===== Utility Functions =====
    
    /**
     * @notice SHA256 hash (using precompile)
     * @param data Input data
     * @return hash SHA256 hash
     */
    // Wrapper to provide a documented named return for NatSpec tools
    function sha256Hash(bytes memory data) internal pure returns (bytes32 hash) {
        return sha256(data);
    }

    // Internal implementation for detectAddressType (called by public forwarder)
    function detectAddressTypeInternal(bytes memory data) internal pure returns (AddressType addrType) {
        if (data.length < 1) return AddressType.UNKNOWN;
        if (data.length >= 4 && data[0] == "b" && data[1] == "c" && data[2] == "1") {
            // Try Bech32 then Bech32m (no mainnet enforcement during detection)
            if (validateBech32Address(data, false, false, false)) return AddressType.BECH32;
            if (validateBech32Address(data, true, false, false)) return AddressType.BECH32M;
            return AddressType.UNKNOWN;
        }
        if (data[0] == "1") return AddressType.P2PKH;
        if (data[0] == "3") return AddressType.P2SH;
        return AddressType.UNKNOWN;
    }
}
