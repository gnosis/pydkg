pragma solidity ^0.4.0;

import {ECCMath} from "github.com/androlo/standard-contracts/contracts/src/crypto/ECCMath.sol";
import {Secp256k1} from "github.com/androlo/standard-contracts/contracts/src/crypto/Secp256k1.sol";


library IntegratedEncryptionScheme {
    function decrypt(bytes ciphertext, uint deckey) returns (uint) {
        // util.validate_private_value(deckey)
        if(deckey >= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
            throw;

        // R = tuple(int.from_bytes(ciphertext[i:i+32], byteorder='big') for i in (0, 32))
        uint[2] memory R;
        assembly {
            // bytes 0x00 to 0x1f encode length of ciphertext
            // so shift everything by 0x20
            mstore(R, mload(add(ciphertext, 0x20)))
            mstore(add(R, 0x20), mload(add(ciphertext, 0x40)))
        }

        // util.validate_curve_point(R)
        if(!Secp256k1.onCurve(R))
            throw;


        // S = bitcoin.fast_multiply(R, deckey)
        uint[3] memory S = Secp256k1._mul(deckey, R);
        ECCMath.toZ1(S, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F);

        // num_trunc_bytes = ord(ciphertext[64:65])
        uint8 numTruncBytes = uint8(ciphertext[64]);

        // iv = ciphertext[65:97]
        uint iv;
        assembly {
            iv := mload(add(ciphertext, 0x61))
        }

        // c = ciphertext[97:-32]
        // if len(c) % 32 != 0:
        //     raise ValueError('enciphered message not properly aligned')
        if(ciphertext.length < 129 || ciphertext.length % 32 != 1)
            throw;

        // kEkM = sha3.keccak_256(S[0].to_bytes(32, byteorder='big')).digest()
        // kE, kM = kEkM[0:16], kEkM[16:32]
        uint kEkM = uint(keccak256(S[0]));
        uint128 kE = uint128(kEkM >> 128);
        uint128 kM = uint128(kEkM & 2**128-1);

        // num_chunks = len(c) // 32
        // message = b''.join((
        //         int.from_bytes(c[32*i:32*(i+1)], 'big') ^
        //         int.from_bytes(sha3.keccak_256(kE + iv + i.to_bytes(32, 'big')).digest(), 'big')
        //     ).to_bytes(32, byteorder='big') for i in range(num_chunks))
        bytes memory message = new bytes(ciphertext.length - 129);
        for(uint i = 0; i < message.length / 32; ++i) {
            uint off = 0x20 + i * 32;
            uint blockCipher = uint(keccak256(kE, iv, i));
            assembly {
                mstore(add(message, off), xor(
                    mload(add(ciphertext, add(97, off))),
                    blockCipher
                ))
            }
        }

        // if num_trunc_bytes > 0:
        //     message, padding = message[:-num_trunc_bytes], message[-num_trunc_bytes:]
        //     if padding != b'\0' * num_trunc_bytes:
        //         raise ValueError('invalid padding')

        if(numTruncBytes > 0) {
            for(i = 0; i < numTruncBytes; i++) {
                if(uint8(message[message.length - i - 1]) != 0)
                    throw;
            }
            assembly {
                mstore(message, sub(mload(message), numTruncBytes))
            }
        }

        // d = ciphertext[-32:]
        assembly {
            kEkM := mload(add(ciphertext, mload(ciphertext)))
            // HACK: Format slice as a bytes object and reassign name ciphertext
            mstore(add(ciphertext, 97), sub(mload(ciphertext), 129))
            ciphertext := add(ciphertext, 97)
        }

        // if d != sha3.keccak_256(kM + c).digest():
        //     raise ValueError('message authentication code does not match')
        if(kEkM != uint(keccak256(kM, ciphertext)))
            throw;

        // return message
        return uint(keccak256(message));
    }
}
