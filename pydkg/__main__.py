import argparse
import asyncio
import logging
import signal
import sys

from py_ecc.secp256k1 import secp256k1

from . import util, networking, ecdkg, db


def main():
    parser = argparse.ArgumentParser(prog='pydkg', description='Distributedly generate some keys yo')
    parser.add_argument('--host', nargs='?', default='0.0.0.0',
                        help='Hostname to serve on (default: %(default)s)')
    parser.add_argument('-p', '--port', type=int, nargs='?', default=8000,
                        help='Port no. to serve on (default: %(default)s)')
    parser.add_argument('--log-level', type=int, nargs='?', default=logging.INFO,
                        help='Logging level (default: %(default)s)')
    parser.add_argument('--log-format', nargs='?', default='%(message)s',
                        help='Logging message format (default: %(default)s)')
    parser.add_argument('--private-key-file', nargs='?', default='private.key',
                        help='File to load private key from (default: %(default)s)')
    parser.add_argument('--addresses-file', nargs='?', default='addresses.txt',
                        help='File to load accepted eth addresses from (default: %(default)s)')
    parser.add_argument('--locations-file', nargs='?', default='locations.txt',
                        help='File containing network locations to attempt connecting with (default: %(default)s)')
    args = parser.parse_args()

    # args parsed; begin getting config stuff
    logging.basicConfig(level=args.log_level, format=args.log_format)

    private_key = util.get_or_generate_private_value(args.private_key_file)
    accepted_addresses = util.get_addresses(args.addresses_file)
    locations = util.get_locations(args.locations_file)

    # initialize some stuff
    db.init()

    node = ecdkg.ECDKGNode.get_by_private_key(private_key)
    accepted_addresses.difference_update((node.address,))

    # display some info and initialize stuff
    logging.debug('own pubkey: ({0[0]:064x}, {0[1]:064x})'.format(node.public_key))
    logging.info('own address: {:040x}'.format(node.address))
    if accepted_addresses:
        logging.info('accepted addresses: {{\n    {}\n}}'.format(
            '\n    '.join('{:040x}'.format(a) for a in accepted_addresses)))
    else:
        logging.warn('not accepting any addresses')

    # get the asyncio event loop
    loop = asyncio.get_event_loop()

    # setup shutdown handlers
    def shutdown():
        logging.info('\nShutting down...')
        loop.stop()

    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, shutdown)

    # main program loop
    loop.run_until_complete(networking.server(args.host, args.port, node, accepted_addresses, loop=loop))
    for hostname, port in locations:
        loop.create_task(networking.attempt_to_establish_channel(hostname, port, node, accepted_addresses))
    loop.create_task(networking.emit_heartbeats())

    try:
        loop.run_forever()
    finally:
        for task in asyncio.Task.all_tasks(loop):
            task.cancel()
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()
        logging.info('Goodbye')


if __name__ == '__main__':
    main()
