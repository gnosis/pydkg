import sqlalchemy.types as types
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy import Column, Integer
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
    python_type = tuple  # (int, int)

    def process_bind_param(self, value, dialect):
        if value is not None:
            return util.curve_point_to_bytes(value)

    def process_result_value(self, value, dialect):
        if value is not None:
            return util.bytes_to_curve_point(value)


class Signature(types.TypeDecorator):
    impl = types.LargeBinary
    python_type = tuple  # rsv (int, int, int)

    def process_bind_param(self, value, dialect):
        if value is not None:
            return util.signature_to_bytes(value)

    def process_result_value(self, value, dialect):
        if value is not None:
            return util.bytes_to_signature(value)


class EthAddress(types.TypeDecorator):
    impl = types.LargeBinary
    python_type = int

    def process_bind_param(self, value, dialect):
        if value is not None:
            return util.address_to_bytes(value)

    def process_result_value(self, value, dialect):
        if value is not None:
            return util.bytes_to_address(value)


class Polynomial(types.TypeDecorator):
    impl = types.LargeBinary
    python_type = tuple

    def process_bind_param(self, value, dialect):
        if value is not None:
            return util.polynomial_to_bytes(value)

    def process_result_value(self, value, dialect):
        if value is not None:
            return util.bytes_to_polynomial(value)


class CurvePointTuple(types.TypeDecorator):
    impl = types.LargeBinary
    python_type = tuple  # of int pairs

    def process_bind_param(self, value, dialect):
        if value is not None:
            return util.curve_point_tuple_to_bytes(value)

    def process_result_value(self, value, dialect):
        if value is not None:
            return util.bytes_to_curve_point_tuple(value)
