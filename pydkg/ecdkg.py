import asyncio
import enum
import functools
import itertools
import logging
import math
import sha3

from py_ecc.secp256k1 import secp256k1

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
    decryption_condition = db.Column(db.String(32), index=True, unique=True)
    phase = db.Column(db.Enum(ECDKGPhase), nullable=False, default=ECDKGPhase.uninitialized)
    threshold = db.Column(db.Integer)
    encryption_key = db.Column(db.CurvePoint)
    decryption_key = db.Column(db.PrivateValue)
    participants = db.relationship('ECDKGParticipant', back_populates='ecdkg')

    secret_poly1 = db.Column(db.Polynomial)
    secret_poly2 = db.Column(db.Polynomial)
    verification_points = db.Column(db.CurvePointTuple)
    encryption_key_part = db.Column(db.CurvePoint)


    @classmethod
    def get_or_create_by_decryption_condition(cls, decryption_condition: str) -> 'ECDKG':
        decryption_condition = util.normalize_decryption_condition(decryption_condition)
        ecdkg_obj = (db.Session
            .query(cls)
            .filter(cls.decryption_condition == decryption_condition)
            .scalar())

        if ecdkg_obj is None:
            ecdkg_obj = cls(decryption_condition=decryption_condition)
            db.Session.add(ecdkg_obj)
            db.Session.commit()

        return ecdkg_obj


    async def run_until_phase(self, target_phase: ECDKGPhase):
        while self.phase < target_phase:
            logging.info('handling {} phase...'.format(self.phase.name))
            await getattr(self, 'handle_{}_phase'.format(self.phase.name))()


    async def handle_uninitialized_phase(self):
        for addr in networking.channels.keys():
            self.get_or_create_participant_by_address(addr)

        # everyone should on agree on participants
        self.threshold = math.ceil(THRESHOLD_FACTOR * (len(self.participants)+1))

        spoly1 = random_polynomial(self.threshold)
        spoly2 = random_polynomial(self.threshold)

        self.secret_poly1 = spoly1
        self.secret_poly2 = spoly2

        self.encryption_key_part = secp256k1.multiply(secp256k1.G, self.secret_poly1[0])

        self.verification_points = tuple(secp256k1.add(secp256k1.multiply(secp256k1.G, a), secp256k1.multiply(G2, b)) for a, b in zip(spoly1, spoly2))

        self.phase = ECDKGPhase.key_distribution
        db.Session.commit()


    async def handle_key_distribution_phase(self):
        signed_secret_shares = await networking.broadcast_jsonrpc_call_on_all_channels(
            'get_signed_secret_shares', self.decryption_condition)

        for participant in self.participants:
            address = participant.eth_address

            if address in signed_secret_shares:
                (share1, share2), rsv = signed_secret_shares[address]

                # TODO: Check signature is valid here

                participant.secret_share1 = share1
                participant.secret_share2 = share2
            else:
                logging.warning('missing share from address {:040x}'.format(address))

        logging.info('set all secret shares')
        verification_points = await networking.broadcast_jsonrpc_call_on_all_channels(
            'get_verification_points', self.decryption_condition)

        for participant in self.participants:
            address = participant.eth_address
            if address in verification_points:
                participant.verification_points = tuple(tuple(int(ptstr[i:i+64], 16) for i in (0, 64)) for ptstr in verification_points[address])
            else:
                logging.warning('missing verification_points from address {:040x}'.format(address))

        self.phase = ECDKGPhase.key_verification
        db.Session.commit()


    async def handle_key_verification_phase(self):
        global own_address

        for participant in self.participants:
            share1 = participant.secret_share1
            share2 = participant.secret_share2

            if share1 is not None and share2 is not None:
                vlhs = secp256k1.add(secp256k1.multiply(secp256k1.G, share1),
                                     secp256k1.multiply(G2, share2))
                vrhs = functools.reduce(secp256k1.add, (secp256k1.multiply(ps, pow(own_address, k, secp256k1.N)) for k, ps in enumerate(participant.verification_points)))

                if vlhs != vrhs:
                    # TODO: Produce complaints and continue instead of halting here
                    raise ProtocolError('verification of shares failed')
            else:
                # TODO: Produce complaints and continue instead of halting here
                raise ProtocolError('missing share from address {:040x}'.format(address))

        self.phase = ECDKGPhase.key_check
        db.Session.commit()


    async def handle_key_check_phase(self):
        # complaints = await networking.broadcast_jsonrpc_call_on_all_channels(
        #     'get_complaints', self.decryption_condition)

        self.phase = ECDKGPhase.key_generation
        db.Session.commit()


    async def handle_key_generation_phase(self):
        encryption_key_parts = await networking.broadcast_jsonrpc_call_on_all_channels(
            'get_encryption_key_part', self.decryption_condition)

        for participant in self.participants:
            address = participant.eth_address
            if address in encryption_key_parts:
                ekp = tuple(int(encryption_key_parts[address][i:i+64], 16) for i in (0, 64))
                participant.encryption_key_part = ekp
            else:
                # TODO: this is supposed to be broadcast... maybe try getting it from other nodes instead?
                raise ProtocolError('missing encryption_key_part from address {:040x}'.format(address))

        self.encryption_key = functools.reduce(secp256k1.add,
            (p.encryption_key_part for p in self.participants), self.encryption_key_part)

        self.phase = ECDKGPhase.key_publication
        db.Session.commit()


    async def handle_key_publication_phase(self):
        await util.decryption_condition_satisfied(self.decryption_condition)

        dec_key_parts = await networking.broadcast_jsonrpc_call_on_all_channels(
            'get_decryption_key_part', self.decryption_condition)

        for p in self.participants:
            address = p.eth_address
            if address in dec_key_parts:
                p.decryption_key_part = int(dec_key_parts[address], 16)
            else:
                # TODO: switch to interpolation of secret shares if waiting doesn't work
                raise ProtocolError('missing decryption key part!')

        self.decryption_key = (sum(p.decryption_key_part for p in self.participants) + self.secret_poly1[0]) % secp256k1.N

        self.phase = ECDKGPhase.complete
        db.Session.commit()


    def get_or_create_participant_by_address(self, address: int) -> 'ECDKGParticipant':
        participant = (db.Session
            .query(ECDKGParticipant)
            .filter(ECDKGParticipant.ecdkg_id == self.id,
                    ECDKGParticipant.eth_address == address)
            .scalar())

        if participant is None:
            participant = ECDKGParticipant(ecdkg_id=self.id, eth_address=address)
            db.Session.add(participant)
            db.Session.commit()

        sfid = (self.id, address)

        return participant


    def get_signed_secret_shares(self, address: int) -> ((int, int), 'rsv triplet'):
        global private_key

        secret_shares = (eval_polynomial(self.secret_poly1, address),
                         eval_polynomial(self.secret_poly2, address))

        msg_hash = sha3.keccak_256(b''.join(util.private_value_to_bytes(s) for s in secret_shares)).digest()

        signature = secp256k1.ecdsa_raw_sign(msg_hash, util.private_value_to_bytes(private_key))

        return (secret_shares, signature)


    def to_state_message(self) -> dict:
        global own_address

        msg = {'address': '{:040x}'.format(own_address)}

        for attr in ('decryption_condition', 'phase', 'threshold'):
            val = getattr(self, attr)
            if val is not None:
                msg[attr] = val

        msg['participants'] = {'{:040x}'.format(p.eth_address): p.to_state_message() for p in self.participants}

        for attr in ('encryption_key', 'encryption_key_part'):
            val = getattr(self, attr)
            if val is not None:
                msg[attr] = '{0[0]:064x}{0[1]:064x}'.format(val)

        vpts = self.verification_points
        if vpts is not None:
            msg['verification_points'] = tuple('{0[0]:064x}{0[1]:064x}'.format(pt) for pt in vpts)

        return msg


class ECDKGParticipant(db.Base):
    ecdkg_id = db.Column(db.Integer, db.ForeignKey('ecdkg.id'))
    ecdkg = db.relationship('ECDKG', back_populates='participants')
    eth_address = db.Column(db.EthAddress, index=True)

    encryption_key_part = db.Column(db.CurvePoint)
    decryption_key_part = db.Column(db.PrivateValue)
    verification_points = db.Column(db.CurvePointTuple)
    secret_share1 = db.Column(db.PrivateValue)
    secret_share2 = db.Column(db.PrivateValue)

    __table_args__ = (db.UniqueConstraint('ecdkg_id', 'eth_address'),)


    def to_state_message(self, address: int = None) -> dict:
        msg = {}

        for attr in ('encryption_key_part', 'verification_points'):
            val = getattr(self, attr)
            if val is not None:
                msg[attr] = '{0[0]:064x}{0[1]:064x}'.format(val)

        return msg
