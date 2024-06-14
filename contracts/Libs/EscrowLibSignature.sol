// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

library EscrowLibSignature {
    struct BeneficiaryInfo {
        uint256 id;
        uint256 deadline;
        address receiver;
    }

    bytes32 constant TYPE_HASH =
        keccak256(
            "BeneficiaryInfo(uint256 id,uint256 deadline,address receiver)"
        );
    
    /**
     @dev Computes the EIP-712 compliant hash of a `BeneficiaryInfo` struct. This hash
     * can be used as part of a signature verification process to ensure the integrity
     * and origin of the data. It constructs a domain separator using the Escrow
     * contract's details and chain ID, and then hashes the concatenation of the EIP-712
     * domain separator, the TYPE_HASH for `BeneficiaryInfo`, and the encoded fields of
     * the `BeneficiaryInfo` struct.
     * @param info The `BeneficiaryInfo` struct containing an `id`, `deadline`, and `receiver` address.
     * @return bytes32 The EIP-712 compliant hash of the `BeneficiaryInfo` struct, ready for use
     * in signature verification.
     */
    function _getHash(
        BeneficiaryInfo memory info
    ) internal view returns (bytes32) {
        bytes32 DOMAIN_HASH = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId)"
                ),
                keccak256("Escrow"),
                keccak256("1.0.0"),
                block.chainid
            )
        );

        bytes32 structHash = keccak256(
            abi.encode(TYPE_HASH, info.id, info.deadline, info.receiver)
        );

        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_HASH, structHash));
    }
}
