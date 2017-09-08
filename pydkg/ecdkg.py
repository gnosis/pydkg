import enum
import functools
import logging
import math

from py_ecc.secp256k1 import secp256k1
from sqlalchemy import types
from sqlalchemy.schema import Column, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship

from . import db, util, networking

COMS_TIMEOUT = 10
THRESHOLD_FACTOR = .5
# NOTE: As soon as I end the python shell session that I created this in
#       and the RAM for that session gets reused, the scalar used to produce
#       this point probably won't come into existence again.
# TODO: reroll this point in dark ritual ala Zcash zkSNARK toxic waste thing
#       ... not that this parameter creates _much_ more security for this
#       protocol, but it's applicable and could be hilarious if you don't
#       believe the above note.
G2 = (0xb25b5ea8b8b230e5574fec0182e809e3455701323968c602ab56b458d0ba96bf,
      0x13edfe75e1c88e030eda220ffc74802144aec67c4e51cb49699d4401c122e19c)
util.validate_curve_point(G2)


def random_polynomial(order: int) -> tuple:
    return tuple(util.random_private_value() for _ in range(order))


def eval_polynomial(poly: tuple, x: int) -> int:
    return sum(c * pow(x, k, secp256k1.N) for k, c in enumerate(poly)) % secp256k1.N


def generate_public_shares(poly1, poly2):
    if len(poly1) != len(poly2):
        raise ValueError('polynomial lengths must match ({} != {})'.format(len(poly1), len(poly2)))

    return (secp256k1.add(secp256k1.multiply(secp256k1.G, a), secp256k1.multiply(G2, b)) for a, b in zip(poly1, poly2))


@enum.unique
class ECDKGPhase(enum.IntEnum):
    uninitialized = 0
    key_distribution = 1
    key_verification = 2
    key_check = 3
    key_generation = 4
    key_publication = 5
    complete = 6


class ECDKG(db.Base):
    __tablename__ = 'ecdkg'

    decryption_condition = Column(types.String(32), index=True, unique=True)
    phase = Column(types.Enum(ECDKGPhase), nullable=False, default=ECDKGPhase.uninitialized)
    threshold = Column(types.Integer)
    encryption_key = Column(db.CurvePoint)
    decryption_key = Column(db.PrivateValue)
    participants = relationship('ECDKGParticipant', back_populates='ecdkg')

    secret_poly1 = Column(db.Polynomial)
    secret_poly2 = Column(db.Polynomial)
    verification_points = Column(db.CurvePointTuple)
    encryption_key_vector = Column(db.CurvePointTuple)

    @classmethod
    def get_or_create_by_decryption_condition(cls, decryption_condition: str) -> 'ECDKG':
        decryption_condition = util.normalize_decryption_condition(decryption_condition)
        ecdkg_obj = (
            db.Session
            .query(cls)
            .filter(cls.decryption_condition == decryption_condition)
            .scalar()
        )

        if ecdkg_obj is None:
            ecdkg_obj = cls(decryption_condition=decryption_condition)
            db.Session.add(ecdkg_obj)
            ecdkg_obj.init()
            db.Session.commit()

        return ecdkg_obj

    def init(self):
        for addr in networking.channels.keys():
            self.get_or_create_participant_by_address(addr)

        # everyone should on agree on participants
        self.threshold = math.ceil(THRESHOLD_FACTOR * (len(self.participants)+1))

        spoly1 = random_polynomial(self.threshold)
        spoly2 = random_polynomial(self.threshold)

        self.secret_poly1 = spoly1
        self.secret_poly2 = spoly2

        self.encryption_key_vector = tuple(secp256k1.multiply(secp256k1.G, coeff) for coeff in self.secret_poly1)

        self.verification_points = tuple(
            secp256k1.add(secp256k1.multiply(secp256k1.G, a), secp256k1.multiply(G2, b))
            for a, b in zip(spoly1, spoly2)
        )

        self.phase = ECDKGPhase.key_distribution

    def process_advance_to_phase(self, target_phase: ECDKGPhase):
        if self.phase < target_phase:
            self.phase = target_phase
            db.Session.commit()

    def process_secret_shares(self, sender_address: int, secret_shares: (int, int), signature: 'rsv triplet'):
        global own_address
        participant = self.get_participant_by_address(sender_address)
        share1, share2 = secret_shares

        msg_bytes = (
            b'SECRETSHARES' +
            self.decryption_condition.encode() +
            util.address_to_bytes(own_address) +
            util.private_value_to_bytes(share1) +
            util.private_value_to_bytes(share2)
        )

        recovered_address = util.address_from_message_and_signature(msg_bytes, signature)

        if sender_address != recovered_address:
            raise ValueError(
                'sender address {:040x} does not match recovered address {:040x}'
                .format(sender_address, recovered_address)
            )

        if participant.secret_share1 is None and participant.secret_share2 is None:
            participant.secret_share1 = share1
            participant.secret_share2 = share2
            participant.shares_signature = signature

            db.Session.commit()
        elif participant.secret_share1 != share1 or participant.secret_share2 != share2:
            participant.get_or_create_complaint_by_complainer_address(own_address)
            raise ValueError(
                '{:040x} sent shares for {} which do not match: {} != {}'
                .format(
                    sender_address,
                    self.decryption_condition,
                    (participant.secret_share1, participant.secret_share2),
                    (share1, share2),
                )
            )

    def process_verification_points(self, sender_address: int, verification_points: tuple, signature: 'rsv triplet'):
        global own_address
        participant = self.get_participant_by_address(sender_address)

        msg_bytes = (
            b'VERIFICATIONPOINTS' +
            self.decryption_condition.encode() +
            util.curve_point_tuple_to_bytes(verification_points)
        )

        recovered_address = util.address_from_message_and_signature(msg_bytes, signature)

        if sender_address != recovered_address:
            raise ValueError(
                'sender address {:040x} does not match recovered address {:040x}'
                .format(sender_address, recovered_address)
            )

        if participant.verification_points is None:
            participant.verification_points = verification_points
            participant.verification_points_signature = signature

            db.Session.commit()
        elif participant.verification_points != verification_points:
            participant.get_or_create_complaint_by_complainer_address(own_address)
            raise ValueError(
                '{:040x} sent verification points for {} which do not match: {} != {}'
                .format(
                    sender_address,
                    self.decryption_condition,
                    participant.verification_points,
                    verification_points,
                )
            )

    def process_secret_share_verification(self, address: int):
        global own_address
        participant = self.get_participant_by_address(address)

        share1 = participant.secret_share1
        share2 = participant.secret_share2

        # TODO: Determine whether this check is necessary
        if share1 is not None and share2 is not None:
            vlhs = secp256k1.add(secp256k1.multiply(secp256k1.G, share1),
                                 secp256k1.multiply(G2, share2))
            vrhs = functools.reduce(
                secp256k1.add,
                (secp256k1.multiply(ps, pow(own_address, k, secp256k1.N))
                    for k, ps in enumerate(participant.verification_points)))

            if vlhs == vrhs:
                return

        participant.get_or_create_complaint_by_complainer_address(own_address)

    def process_encryption_key_vector(self,
                                      sender_address: int,
                                      encryption_key_vector: tuple,
                                      signature: 'rsv triplet'):
        global own_address
        participant = self.get_participant_by_address(sender_address)

        msg_bytes = (
            b'ENCRYPTIONKEYPART' +
            self.decryption_condition.encode() +
            util.curve_point_tuple_to_bytes(encryption_key_vector)
        )

        recovered_address = util.address_from_message_and_signature(msg_bytes, signature)

        if sender_address != recovered_address:
            raise ValueError(
                'sender address {:040x} does not match recovered address {:040x}'
                .format(sender_address, recovered_address)
            )

        if participant.encryption_key_vector is None:
            lhs = secp256k1.multiply(secp256k1.G, participant.secret_share1)
            rhs = functools.reduce(
                secp256k1.add,
                (secp256k1.multiply(ps, pow(own_address, k, secp256k1.N))
                    for k, ps in enumerate(encryption_key_vector)))
            if lhs != rhs:
                participant.get_or_create_complaint_by_complainer_address(own_address)
                raise ValueError(
                    '{:040x} sent enc key vector which does not match previously sent secret share'
                    .format(sender_address)
                )

            participant.encryption_key_vector = encryption_key_vector
            participant.encryption_key_vector_signature = signature

            if all(p.encryption_key_vector is not None for p in self.participants):
                self.encryption_key = functools.reduce(
                    secp256k1.add,
                    (p.encryption_key_vector[0] for p in self.participants),
                    self.encryption_key_vector[0]
                )

            db.Session.commit()
        elif participant.encryption_key_vector != encryption_key_vector:
            participant.get_or_create_complaint_by_complainer_address(own_address)
            raise ValueError(
                '{:040x} sent encryption key part for {} which do not match: {} != {}'
                .format(
                    sender_address,
                    self.decryption_condition,
                    participant.encryption_key_vector,
                    encryption_key_vector,
                )
            )

    def process_decryption_key_part(self,
                                    sender_address: int,
                                    decryption_key_part: int,
                                    signature: 'rsv triplet'):
        participant = self.get_participant_by_address(sender_address)

        msg_bytes = (
            b'DECRYPTIONKEYPART' +
            self.decryption_condition.encode() +
            util.private_value_to_bytes(decryption_key_part)
        )

        recovered_address = util.address_from_message_and_signature(msg_bytes, signature)

        if sender_address != recovered_address:
            raise ValueError(
                'sender address {:040x} does not match recovered address {:040x}'
                .format(sender_address, recovered_address)
            )

        # TODO: verify decryption key part

        if participant.decryption_key_part is None:
            participant.decryption_key_part = decryption_key_part
            participant.decryption_key_part_signature = signature

            if all(p.decryption_key_part is not None for p in self.participants):
                self.decryption_key = (
                    sum(p.decryption_key_part for p in self.participants) +
                    self.secret_poly1[0]
                ) % secp256k1.N

            db.Session.commit()
        elif participant.decryption_key_part != decryption_key_part:
            participant.get_or_create_complaint_by_complainer_address(own_address)
            raise ValueError(
                '{:040x} sent decryption key part for {} which do not match: {} != {}'
                .format(
                    sender_address,
                    self.decryption_condition,
                    participant.decryption_key_part,
                    decryption_key_part,
                )
            )

    async def run_until_phase(self, target_phase: ECDKGPhase):
        while self.phase < target_phase:
            logging.info('handling {} phase...'.format(self.phase.name))
            await getattr(self, 'handle_{}_phase'.format(self.phase.name))()

    async def handle_key_distribution_phase(self):
        signed_secret_shares = await networking.broadcast_jsonrpc_call_on_all_channels(
            'get_signed_secret_shares', self.decryption_condition)

        for participant in self.participants:
            address = participant.eth_address

            if address not in signed_secret_shares:
                logging.warning('missing shares from address {:040x}'.format(address))
                continue

            try:
                self.process_secret_shares(address, *signed_secret_shares[address])
            except Exception as e:
                logging.warning(
                    'exception occurred while processing secret shares from {:040x}: {}'
                    .format(address, e)
                )

        logging.info('set all secret shares')
        signed_verification_points = await networking.broadcast_jsonrpc_call_on_all_channels(
            'get_signed_verification_points', self.decryption_condition)

        for participant in self.participants:
            address = participant.eth_address

            if address not in signed_verification_points:
                logging.warning('missing verification points from address {:040x}'.format(address))
                continue

            try:
                self.process_verification_points(address, *signed_verification_points[address])
            except Exception as e:
                logging.warning(
                    'exception occurred while processing verification points from {:040x}: {}'
                    .format(address, e)
                )

        self.process_advance_to_phase(ECDKGPhase.key_verification)

    async def handle_key_verification_phase(self):
        for participant in self.participants:
            try:
                self.process_secret_share_verification(participant.eth_address)
            except Exception as e:
                logging.warning(
                    'exception occurred while verifying shares from {:040x}: {}'
                    .format(participant.eth_address, e)
                )

        self.process_advance_to_phase(ECDKGPhase.key_check)

    async def handle_key_check_phase(self):
        complaints = await networking.broadcast_jsonrpc_call_on_all_channels(
            'get_complaints', self.decryption_condition)

        for participant in self.participants:
            complainer_address = participant.eth_address

            if complainer_address not in complaints:
                logging.warning('missing complaints from address {:040x}'.format(complainer_address))
                continue

            # TODO: Add complaints and collect responses to complaints

        self.process_advance_to_phase(ECDKGPhase.key_generation)

    async def handle_key_generation_phase(self):
        signed_encryption_key_vectors = await networking.broadcast_jsonrpc_call_on_all_channels(
            'get_signed_encryption_key_vector', self.decryption_condition)

        for participant in self.participants:
            address = participant.eth_address

            if address not in signed_encryption_key_vectors:
                # TODO: this is supposed to be broadcast... maybe try getting it from other nodes instead?
                logging.warning('missing encryption key part from address {:040x}'.format(address))
                continue

            try:
                self.process_encryption_key_vector(address, *signed_encryption_key_vectors[address])
            except Exception as e:
                logging.warning(
                    'exception occurred while processing encryption key part from {:040x}: {}'
                    .format(address, e)
                )

        self.process_advance_to_phase(ECDKGPhase.key_publication)

    async def handle_key_publication_phase(self):
        await util.decryption_condition_satisfied(self.decryption_condition)

        signed_decryption_key_parts = await networking.broadcast_jsonrpc_call_on_all_channels(
            'get_signed_decryption_key_part', self.decryption_condition)

        for p in self.participants:
            address = p.eth_address

            if address not in signed_decryption_key_parts:
                # TODO: switch to interpolation of secret shares if waiting doesn't work
                logging.warning('missing decryption key part from address {:040x}'.format(address))
                continue

            try:
                self.process_decryption_key_part(address, *signed_decryption_key_parts[address])
            except Exception as e:
                logging.warning(
                    'exception occurred while processing decryption key part from {:040x}: {}'
                    .format(address, e)
                )

        self.process_advance_to_phase(ECDKGPhase.complete)

    def get_participant_by_address(self, address: int) -> 'ECDKGParticipant':
        participant = (
            db.Session
            .query(ECDKGParticipant)
            .filter(ECDKGParticipant.ecdkg_id == self.id,
                    ECDKGParticipant.eth_address == address)
            .scalar()
        )

        if participant is None:
            raise ValueError('could not find participant with address {:040x}'.format(address))

        return participant

    def get_or_create_participant_by_address(self, address: int) -> 'ECDKGParticipant':
        try:
            return self.get_participant_by_address(address)
        except ValueError:
            participant = ECDKGParticipant(ecdkg_id=self.id, eth_address=address)
            db.Session.add(participant)
            db.Session.commit()
            return participant

    def get_signed_secret_shares(self, address: int) -> ((int, int), 'rsv triplet'):
        global private_key

        secret_shares = (eval_polynomial(self.secret_poly1, address),
                         eval_polynomial(self.secret_poly2, address))

        msg_bytes = (
            b'SECRETSHARES' +
            self.decryption_condition.encode() +
            util.address_to_bytes(address) +
            util.private_value_to_bytes(secret_shares[0]) +
            util.private_value_to_bytes(secret_shares[1])
        )

        signature = util.sign_with_key(msg_bytes, private_key)

        return (secret_shares, signature)

    def get_signed_verification_points(self) -> (tuple, 'rsv triplet'):
        global private_key

        msg_bytes = (
            b'VERIFICATIONPOINTS' +
            self.decryption_condition.encode() +
            util.curve_point_tuple_to_bytes(self.verification_points)
        )

        signature = util.sign_with_key(msg_bytes, private_key)

        return (self.verification_points, signature)

    def get_signed_encryption_key_vector(self) -> ((int, int), 'rsv triplet'):
        global private_key

        msg_bytes = (
            b'ENCRYPTIONKEYPART' +
            self.decryption_condition.encode() +
            util.curve_point_tuple_to_bytes(self.encryption_key_vector)
        )

        signature = util.sign_with_key(msg_bytes, private_key)

        return (self.encryption_key_vector, signature)

    def get_signed_decryption_key_part(self) -> (int, 'rsv triplet'):
        global private_key

        msg_bytes = (
            b'DECRYPTIONKEYPART' +
            self.decryption_condition.encode() +
            util.private_value_to_bytes(self.secret_poly1[0])
        )

        signature = util.sign_with_key(msg_bytes, private_key)

        return (self.secret_poly1[0], signature)

    def get_complaints_by(self, address: int) -> dict:
        return (
            db.Session
            .query(ECDKGComplaint)
            .filter(  # ECDKGComplaint.participant.ecdkg_id == self.id,
                    ECDKGComplaint.complainer_address == address)
            .all()
        )

    def to_state_message(self) -> dict:
        global own_address

        msg = {'address': '{:040x}'.format(own_address)}

        for attr in ('decryption_condition', 'phase', 'threshold'):
            val = getattr(self, attr)
            if val is not None:
                msg[attr] = val

        msg['participants'] = {'{:040x}'.format(p.eth_address): p.to_state_message() for p in self.participants}

        for attr in ('encryption_key',):
            val = getattr(self, attr)
            if val is not None:
                msg[attr] = '{0[0]:064x}{0[1]:064x}'.format(val)

        for attr in ('verification_points', 'encryption_key_vector'):
            val = getattr(self, attr)
            if val is not None:
                msg[attr] = tuple('{0[0]:064x}{0[1]:064x}'.format(pt) for pt in val)

        return msg


class ECDKGParticipant(db.Base):
    __tablename__ = 'ecdkg_participant'

    ecdkg_id = Column(types.Integer, ForeignKey('ecdkg.id'))
    ecdkg = relationship('ECDKG', back_populates='participants')
    eth_address = Column(db.EthAddress, index=True)

    encryption_key_vector = Column(db.CurvePointTuple)
    encryption_key_vector_signature = Column(db.Signature)

    decryption_key_part = Column(db.PrivateValue)
    decryption_key_part_signature = Column(db.Signature)

    verification_points = Column(db.CurvePointTuple)
    verification_points_signature = Column(db.Signature)

    secret_share1 = Column(db.PrivateValue)
    secret_share2 = Column(db.PrivateValue)
    shares_signature = Column(db.Signature)

    complaints = relationship('ECDKGComplaint', back_populates='participant')

    __table_args__ = (UniqueConstraint('ecdkg_id', 'eth_address'),)

    def get_or_create_complaint_by_complainer_address(self, address: int) -> 'ECDKGComplaint':
        complaint = (
            db.Session
            .query(ECDKGComplaint)
            .filter(ECDKGComplaint.participant_id == self.id,
                    ECDKGComplaint.complainer_address == address)
            .scalar()
        )

        if complaint is None:
            complaint = ECDKGComplaint(participant_id=self.id, complainer_address=address)
            db.Session.add(complaint)
            db.Session.commit()

        return complaint

    def to_state_message(self, address: int = None) -> dict:
        msg = {}

        for attr in ('verification_points', 'encryption_key_vector'):
            val = getattr(self, attr)
            if val is not None:
                msg[attr] = tuple('{0[0]:064x}{0[1]:064x}'.format(pt) for pt in val)

        return msg


class ECDKGComplaint(db.Base):
    __tablename__ = 'ecdkg_complaint'

    participant_id = Column(types.Integer, ForeignKey('ecdkg_participant.id'))
    participant = relationship('ECDKGParticipant', back_populates='complaints')
    complainer_address = Column(db.EthAddress, index=True)

    __table_args__ = (UniqueConstraint('participant_id', 'complainer_address'),)
