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
    if (any(coord < 0 or coord >= secp256k1.P for coord in point) or
        pow(point[1], 2, secp256k1.P) != (pow(point[0], 3, secp256k1.P) + 7) % secp256k1.P
       ) and point != (0, 0): # (0, 0) is used to represent group identity
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
    util.validate_private_value(value)
    return value.to_bytes(32, byteorder='big')


def bytes_to_private_value(bts: bytes) -> int:
    priv = int.from_bytes(bts, byteorder='big')
    util.validate_private_value(priv)
    return priv


def sequence_256_bit_values_to_bytes(sequence: tuple) -> bytes:
    return b''.join(map(functools.partial(int.to_bytes, length=32, byteorder='big'), sequence))


def private_value_to_eth_address(private_value: int) -> int:
    return curve_point_to_eth_address(secp256k1.multiply(secp256k1.G, private_value))


def curve_point_to_eth_address(curve_point: (int, int)) -> int:
    return int.from_bytes(sha3.keccak_256(sequence_256_bit_values_to_bytes(curve_point)).digest()[-20:], byteorder='big')


###########################
# Configuration utilities #
###########################


PRIVATE_VALUE_RE = re.compile(r'(?P<optprefix>0x)?(?P<value>[0-9A-Fa-f]{64})')
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


ADDRESS_RE = re.compile(r'(?P<optprefix>0x)?(?P<value>[0-9A-Fa-f]{40})')
def get_addresses(filepath: str) -> set:
    with open(filepath, 'r') as f:
        return set(int(m.group('value'), 16) for m in filter(lambda v: v is not None, (ADDRESS_RE.fullmatch(l.strip()) for l in f)))


LOCATION_RE = re.compile(r'(?P<hostname>[^:]*)(?::(?P<port>\d+))?')
DEFAULT_PORT = 80
def get_locations(filepath: str) -> list:
    with open(filepath, 'r') as f:
        return list((m.group('hostname'), int(m.group('port') or DEFAULT_PORT)) for m in filter(lambda v: v is not None, (LOCATION_RE.fullmatch(l.strip()) for l in f if not l.startswith('#'))))


###################
# Other utilities #
###################


def random_private_value() -> int:
    return random.randrange(secp256k1.N)


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
