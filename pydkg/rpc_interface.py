import asyncio
import functools
import logging

from jsonrpc.dispatcher import Dispatcher

from . import ecdkg, util


class ProtocolError(Exception):
    pass


def create_dispatcher(address: int = None):
    # TODO: make loop use uniform
    loop = asyncio.get_event_loop()

    dispatcher = Dispatcher()

    dispatcher['echo'] = lambda value: value

    def dispatcher_add_async_method(corofunc):
        @functools.wraps(corofunc)
        def wrapper(*args, **kwargs):
            return loop.create_task(corofunc(*args, **kwargs))
        return dispatcher.add_method(wrapper)

    @dispatcher_add_async_method
    async def get_ecdkg_state(decryption_condition: str, phase: ecdkg.ECDKGPhase = ecdkg.ECDKGPhase.uninitialized):
        ecdkg_obj = ecdkg.ECDKG.get_or_create_by_decryption_condition(decryption_condition)
        return ecdkg_obj.to_state_message()

    @dispatcher_add_async_method
    async def get_encryption_key(decryption_condition, notify_others=True):
        ecdkg_obj = ecdkg.ECDKG.get_or_create_by_decryption_condition(decryption_condition)
        await ecdkg_obj.run_until_phase(ecdkg.ECDKGPhase.key_publication)
        return '{0[0]:064x}{0[1]:064x}'.format(ecdkg_obj.encryption_key)

    @dispatcher_add_async_method
    async def get_signed_decryption_key_part(decryption_condition):
        # TODO: Is running the get enc key even necessary now?
        await get_encryption_key(decryption_condition)
        await util.decryption_condition_satisfied(decryption_condition)
        ecdkg_obj = ecdkg.ECDKG.get_or_create_by_decryption_condition(decryption_condition)
        return ecdkg_obj.get_signed_decryption_key_part()

    @dispatcher_add_async_method
    async def get_decryption_key(decryption_condition):
        ecdkg_obj = ecdkg.ECDKG.get_or_create_by_decryption_condition(decryption_condition)
        await ecdkg_obj.run_until_phase(ecdkg.ECDKGPhase.complete)
        return '{:064x}'.format(ecdkg_obj.decryption_key)

    @dispatcher_add_async_method
    async def get_signed_verification_points(decryption_condition):
        logging.info('sending vpoints to {:040x}'.format(address))
        ecdkg_obj = ecdkg.ECDKG.get_or_create_by_decryption_condition(decryption_condition)
        await ecdkg_obj.run_until_phase(ecdkg.ECDKGPhase.key_distribution)
        return ecdkg_obj.get_signed_verification_points()

    @dispatcher_add_async_method
    async def get_signed_encryption_key_vector(decryption_condition):
        ecdkg_obj = ecdkg.ECDKG.get_or_create_by_decryption_condition(decryption_condition)
        # await ecdkg_obj.run_until_phase(ecdkg.ECDKGPhase.key_generation)
        await ecdkg_obj.run_until_phase(ecdkg.ECDKGPhase.key_distribution)
        return ecdkg_obj.get_signed_encryption_key_vector()

    @dispatcher_add_async_method
    async def get_complaints(decryption_condition):
        ecdkg_obj = ecdkg.ECDKG.get_or_create_by_decryption_condition(decryption_condition)
        # await ecdkg_obj.run_until_phase(ecdkg.ECDKGPhase.key_check)
        await ecdkg_obj.run_until_phase(ecdkg.ECDKGPhase.key_distribution)
        complaints = ecdkg_obj.get_complaints_by(ecdkg.own_address)
        logging.info('sending complaints: {}'.format(complaints))
        return complaints

    if address is not None:
        @dispatcher_add_async_method
        async def get_signed_secret_shares(decryption_condition):
            logging.info('sending shares to {:040x}'.format(address))
            ecdkg_obj = ecdkg.ECDKG.get_or_create_by_decryption_condition(decryption_condition)
            await ecdkg_obj.run_until_phase(ecdkg.ECDKGPhase.key_distribution)
            return ecdkg_obj.get_signed_secret_shares(address)

    return dispatcher
