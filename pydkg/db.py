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
            return util.private_value_to_bytes(value)

    def process_result_value(self, value, dialect):
        if value is not None:
            return util.bytes_to_private_value(value)


class CurvePoint(types.TypeDecorator):
    impl = types.LargeBinary
    python_type = tuple # (int, int)

    def process_bind_param(self, value, dialect):
        if value is not None:
            util.validate_curve_point(value)
            return util.sequence_256_bit_values_to_bytes(value)

    def process_result_value(self, value, dialect):
        if value is not None:
            return util.bytes_to_curve_point(value)

class Signature(types.TypeDecorator):
    impl = types.LargeBinary
    python_type = tuple # rsv (int, int, int)

    def process_bind_param(self, value, dialect):
        if value is not None:
            util.validate_signature(value)
            return tuple(int.to_bytes(part, partsize, byteorder='big') for part, partsize in zip(value, (32, 32, 1)))

    def process_result_value(self, value, dialect):
        if value is not None:
            return util.bytes_to_signature(value)

class EthAddress(types.TypeDecorator):
    impl = types.LargeBinary
    python_type = int

    def process_bind_param(self, value, dialect):
        if value is not None:
            util.validate_eth_address(value)
            return value.to_bytes(20, byteorder='big')

    def process_result_value(self, value, dialect):
        if value is not None:
            return util.bytes_to_address(value)


class Polynomial(types.TypeDecorator):
    impl = types.LargeBinary
    python_type = tuple

    def process_bind_param(self, value, dialect):
        if value is not None:
            util.validate_polynomial(value)
            return util.sequence_256_bit_values_to_bytes(value)

    def process_result_value(self, value, dialect):
        if value is not None:
            return util.bytes_to_polynomial(value)


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
            return util.bytes_to_curve_point_tuple(value)