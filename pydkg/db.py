import math

import sqlalchemy.types as types
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker, relationship
from sqlalchemy import Column, Integer, String, Enum, ForeignKey
from sqlalchemy.schema import UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base, declared_attr

from . import util


class Base(object):
    @declared_attr
    def __tablename__(cls):
        return cls.__name__.lower()

    id = Column(Integer, primary_key=True)

Base = declarative_base(cls=Base)


def init():
    global engine, Session
    engine = create_engine('sqlite:///:memory:')
    Session = scoped_session(sessionmaker(engine))
    Base.metadata.create_all(engine)


class PrivateValue(types.TypeDecorator):
    impl = types.LargeBinary
    python_type = int

    def process_bind_param(self, value, dialect):
        if value is not None:
            util.validate_private_value(value)
            return value.to_bytes(32, byteorder='big')

    def process_result_value(self, value, dialect):
        if value is not None:
            priv = int.from_bytes(value, byteorder='big')
            util.validate_private_value(priv)
            return priv


class CurvePoint(types.TypeDecorator):
    impl = types.LargeBinary
    python_type = tuple # (int, int)

    def process_bind_param(self, value, dialect):
        if value is not None:
            util.validate_curve_point(value)
            return util.sequence_256_bit_values_to_bytes(value)

    def process_result_value(self, value, dialect):
        if value is not None:
            if len(value) != 64:
                raise ValueError('unexpected result value length {} bytes'.format(len(value)))
            point = tuple(int.from_bytes(value[i:i+32], byteorder='big') for i in (0, 32))
            util.validate_curve_point(point)
            return point


class Signature(types.TypeDecorator):
    impl = types.LargeBinary
    python_type = tuple # rsv (int, int, int)

    def process_bind_param(self, value, dialect):
        if value is not None:
            util.validate_signature(value)
            return tuple(int.to_bytes(part, partsize, byteorder='big') for part, partsize in zip(value, (32, 32, 1)))

    def process_result_value(self, value, dialect):
        if value is not None:
            if len(value) != 65:
                raise ValueError('unexpected result value length {} bytes'.format(len(value)))
            signature = tuple(int.from_bytes(bs, byteorder='big') for bs in (value[0:32], value[32:64], value[64:]))
            util.validate_signature(signature)
            return signature


class EthAddress(types.TypeDecorator):
    impl = types.LargeBinary
    python_type = int

    def process_bind_param(self, value, dialect):
        if value is not None:
            util.validate_eth_address(value)
            return value.to_bytes(20, byteorder='big')

    def process_result_value(self, value, dialect):
        if value is not None:
            addr = int.from_bytes(value, byteorder='big')
            util.validate_eth_address(addr)
            return addr


class Polynomial(types.TypeDecorator):
    impl = types.LargeBinary
    python_type = tuple

    def process_bind_param(self, value, dialect):
        if value is not None:
            util.validate_polynomial(value)
            return util.sequence_256_bit_values_to_bytes(value)

    def process_result_value(self, value, dialect):
        if value is not None:
            if len(value) % 32 != 0:
                raise ValueError('result value length {} not divisible by 32 bytes'.format(len(value)))
            polynomial = tuple(int.from_bytes(value[i:i+32], byteorder='big') for i in range(0, len(value), 32))
            util.validate_polynomial(polynomial)
            return polynomial


class CurvePointTuple(types.TypeDecorator):
    impl = types.LargeBinary
    python_type = tuple # of int pairs

    def process_bind_param(self, value, dialect):
        if value is not None:
            def validated_convert(point):
                util.validate_curve_point(point)
                return util.sequence_256_bit_values_to_bytes(point)

            return b''.join(validated_convert(point) for point in value)

    def process_result_value(self, value, dialect):
        if value is not None:
            if len(value) % 64 != 0:
                raise ValueError('result value length {} not divisible by 64 bytes'.format(len(value)))
            points = tuple(tuple(int.from_bytes(value[i+j:i+j+32], byteorder='big') for i in (0, 32)) for j in range(0, len(value), 64))
            for point in points:
                util.validate_curve_point(point)
            return points
