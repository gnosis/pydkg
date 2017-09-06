import asyncio
import functools
import logging
import os
import re

from datetime import datetime

from py_ecc.secp256k1 import secp256k1
import sha3

from dateutil.parser import parse as parse_datetime
from dateutil.tz import tzutc

try:
    from secrets import SystemRandom
    random = SystemRandom()
except ImportError:
    try:
        from random import SystemRandom
        random = SystemRandom()
    except ImportError:
        logging.warninging('Could not obtain randomness source suitable for crypto')
        import random


########################
# Validation utilities #
########################


def validate_private_value(value: int):
    if value < 0 or value >= secp256k1.N:
        raise ValueError('invalid EC private value {:064x}'.format(value))


def validate_polynomial(polynomial: int):
    for i, coeff in enumerate(polynomial):
        try:
            validate_private_value(coeff)
        except ValueError:
            raise ValueError('invalid x^{} coefficient {:064x}'.format(i, coeff))


def validate_curve_point(point: (int, int)):
    if (
        any(coord < 0 or coord >= secp256k1.P for coord in point) or
        pow(point[1], 2, secp256k1.P) != (pow(point[0], 3, secp256k1.P) + 7) % secp256k1.P
    ) and point != (0, 0):  # (0, 0) is used to represent group identity element
        raise ValueError('invalid EC point {}'.format(point))


def validate_eth_address(addr: int):
    if addr < 0 or addr >= 2**160:
        raise ValueError('invalid Ethereum address {:040x}'.format(addr))


def validate_signature(signature: 'rsv triplet'):
    r, s, v = signature
    if (any(coord < 0 or coord >= secp256k1.P for coord in (r, s)) or
       v not in (27, 28)):
        raise ValueError('invalid signature {}'.format(signature))


########################
# Conversion utilities #
########################


def private_value_to_bytes(value: int) -> bytes:
    validate_private_value(value)
    return value.to_bytes(32, byteorder='big')


def bytes_to_private_value(bts: bytes) -> int:
    priv = int.from_bytes(bts, byteorder='big')
    validate_private_value(priv)
    return priv


def curve_point_to_bytes(point: (int, int)) -> bytes:
    validate_curve_point(point)
    return sequence_256_bit_values_to_bytes(point)


def bytes_to_curve_point(bts: bytes) -> (int, int):
    if len(bts) != 64:
        raise ValueError('unexpected length {} bytes'.format(len(bts)))
    point = tuple(int.from_bytes(bts[i:i+32], byteorder='big') for i in (0, 32))
    validate_curve_point(point)
    return point


def signature_to_bytes(signature: 'rsv triplet') -> bytes:
    validate_signature(signature)
    return b''.join(int.to_bytes(part, partsize, byteorder='big') for part, partsize in zip(signature, (32, 32, 1)))


def bytes_to_signature(bts: bytes) -> 'rsv triplet':
    if len(bts) != 65:
        raise ValueError('unexpected length {} bytes'.format(len(bts)))
    signature = tuple(int.from_bytes(bs, byteorder='big') for bs in (bts[0:32], bts[32:64], bts[64:]))
    validate_signature(signature)
    return signature


def address_to_bytes(addr: int) -> bytes:
    validate_eth_address(addr)
    return addr.to_bytes(20, byteorder='big')


def bytes_to_address(bts: bytes) -> int:
    if len(bts) != 20:
        raise ValueError('unexpected length {} bytes'.format(len(bts)))
    addr = int.from_bytes(bts, byteorder='big')
    validate_eth_address(addr)
    return addr


def polynomial_to_bytes(polynomial: tuple) -> bytes:
    validate_polynomial(polynomial)
    return sequence_256_bit_values_to_bytes(polynomial)


def bytes_to_polynomial(bts: bytes) -> tuple:
    if len(bts) % 32 != 0:
        raise ValueError('length {} not divisible by 32 bytes'.format(len(bts)))
    polynomial = tuple(int.from_bytes(bts[i:i+32], byteorder='big') for i in range(0, len(bts), 32))
    validate_polynomial(polynomial)
    return polynomial


def curve_point_tuple_to_bytes(points: tuple) -> bytes:
    return b''.join(curve_point_to_bytes(point) for point in points)


def bytes_to_curve_point_tuple(bts: bytes) -> tuple:
    if len(bts) % 64 != 0:
        raise ValueError('length {} not divisible by 64 bytes'.format(len(bts)))
    return tuple(bytes_to_curve_point(bts[i:i+64]) for i in range(0, len(bts), 64))


def sequence_256_bit_values_to_bytes(sequence: tuple) -> bytes:
    return b''.join(map(functools.partial(int.to_bytes, length=32, byteorder='big'), sequence))


def private_value_to_eth_address(private_value: int) -> int:
    return curve_point_to_eth_address(secp256k1.multiply(secp256k1.G, private_value))


def curve_point_to_eth_address(curve_point: (int, int)) -> int:
    return int.from_bytes(sha3.keccak_256(curve_point_to_bytes(curve_point)).digest()[-20:], byteorder='big')


###########################
# Configuration utilities #
###########################

PRIVATE_VALUE_RE = re.compile(r'(?P<optprefix>0x)?(?P<value>[0-9A-Fa-f]{64})')
ADDRESS_RE = re.compile(r'(?P<optprefix>0x)?(?P<value>[0-9A-Fa-f]{40})')
LOCATION_RE = re.compile(r'(?P<hostname>[^:]*)(?::(?P<port>\d+))?')
DEFAULT_PORT = 80


def get_or_generate_private_value(filepath: str) -> int:
    if os.path.isfile(filepath):
        with open(filepath) as private_key_fp:
            private_key_str = private_key_fp.read().strip()
            private_key_match = PRIVATE_VALUE_RE.fullmatch(private_key_str)
            if private_key_match:
                private_key = int(private_key_match.group('value'), 16)
                validate_private_value(private_key)
                return private_key

    logging.warning('could not read key from private key file {}; generating new value...'.format(filepath))
    with open(filepath, 'w') as private_key_fp:
        private_key = random_private_value()
        private_key_fp.write('{:064x}\n'.format(private_key))
        return private_key


def get_addresses(filepath: str) -> set:
    with open(filepath, 'r') as f:
        return set(
            int(m.group('value'), 16)
            for m in filter(lambda v: v is not None, (ADDRESS_RE.fullmatch(l.strip()) for l in f))
        )


def get_locations(filepath: str) -> list:
    with open(filepath, 'r') as f:
        return list(
            (m.group('hostname'), int(m.group('port') or DEFAULT_PORT))
            for m in filter(
                lambda v: v is not None,
                (LOCATION_RE.fullmatch(l.strip()) for l in f if not l.startswith('#'))
            )
        )


###################
# Other utilities #
###################


def random_private_value() -> int:
    return random.randrange(secp256k1.N)


def address_from_message_and_signature(message: bytes,
                                       signature: 'rsv triplet',
                                       hash: 'hash class' = sha3.keccak_256) -> int:
    if hash is None:
        value = message
    else:
        value = hash(message).digest()

    if len(value) != 32:
        raise ValueError('value must have length 32 but got length {} ({})'.format(len(value), value))

    (r, s, v) = signature

    pubkey = secp256k1.ecdsa_raw_recover(value, (v, r, s))

    if not pubkey:
        raise ValueError('ECDSA public key recovery failed with bytes {} and signature {}'.format(value, signature))

    return curve_point_to_eth_address(pubkey)


def sign_with_key(message: bytes, key: int, hash: 'hash class' = sha3.keccak_256) -> 'rsv triplet':
    if hash is None:
        value = message
    else:
        value = hash(message).digest()

    if len(value) != 32:
        raise ValueError('value must have length 32 but got length {} ({})'.format(len(value), value))

    v, r, s = secp256k1.ecdsa_raw_sign(value, private_value_to_bytes(key))
    return (r, s, v)


def normalize_decryption_condition(deccond: str, return_obj: bool = False):
    prefix = 'past '
    if deccond.startswith(prefix):
        try:
            dt = parse_datetime(deccond[len(prefix):])
        except ValueError as e:
            raise ValueError('could not parse date for "past" condition from string "{}"'.format(deccond[len(prefix):]))

        # All time values internally UTC
        if dt.tzinfo is not None:
            dt = dt.astimezone(tzutc())

        # Strip out subsecond info and make naive
        dt = dt.replace(microsecond=0, tzinfo=None)

        if return_obj:
            return (prefix, dt)

        return prefix + dt.isoformat()

    raise ValueError('invalid decryption condition {}'.format(deccond))


async def decryption_condition_satisfied(deccond: str) -> bool:
    prefix, obj = normalize_decryption_condition(deccond, True)
    if prefix == 'past ':
        while datetime.utcnow() < obj:
            await asyncio.sleep(max(0, (obj - datetime.utcnow()).total_seconds()))
