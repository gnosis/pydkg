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


    logging.basicConfig(level=args.log_level, format=args.log_format)

    ecdkg.private_key = util.get_or_generate_private_value(args.private_key_file)
    own_public_key = secp256k1.multiply(secp256k1.G, ecdkg.private_key)
    ecdkg.own_address = util.curve_point_to_eth_address(own_public_key)
    ecdkg.accepted_addresses = util.get_addresses(args.addresses_file)
    ecdkg.accepted_addresses.difference_update((ecdkg.own_address,))
    locations = util.get_locations(args.locations_file)


    logging.debug('own pubkey: ({0[0]:064x}, {0[1]:064x})'.format(own_public_key))
    logging.info('own address: {:040x}'.format(ecdkg.own_address))
    if ecdkg.accepted_addresses:
        logging.info('accepted addresses: {{\n    {}\n}}'.format(
            '\n    '.join('{:040x}'.format(a) for a in ecdkg.accepted_addresses)))
    else:
        logging.warn('not accepting any addresses')

    db.init()


    def shutdown(signum, frame):
        logging.info('\nShutting down...')
        sys.exit()

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, shutdown)


    loop = asyncio.get_event_loop()
    loop.run_until_complete(networking.server(args.host, args.port, loop=loop))
    for hostname, port in locations:
        loop.create_task(networking.attempt_to_establish_channel(hostname, port))
    loop.create_task(networking.emit_heartbeats())

    try:
        loop.run_forever()
    except SystemExit:
        pass
    finally:
        for task in asyncio.Task.all_tasks(loop):
            task.cancel()
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()
        logging.info('Goodbye')

if __name__ == '__main__':
    main()
