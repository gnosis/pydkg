import asyncio
import collections
import json
import logging
import uuid

from http.server import BaseHTTPRequestHandler

from jsonrpc import JSONRPCResponseManager

from . import util, ecdkg, rpc_interface, db


DEFAULT_TIMEOUT = 120
HEARTBEAT_INTERVAL = 30

LineReader = collections.namedtuple('LineReader', ('readline'))


# Adapted from http://stackoverflow.com/a/5955949
# but made to work (synchronously) with asyncio.StreamReader
class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, raw_requestline, stream_reader):
        self.raw_requestline = raw_requestline
        self.stream_reader = stream_reader
        self.error_code = self.error_message = None

        def rfile_readline(_):
            gen = self.stream_reader.readline()
            try:
                while True:
                    next(gen)
            except StopIteration as stop:
                return stop.value
        self.rfile = LineReader(readline=rfile_readline)
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

    def __repr__(self):
        return '<{module}.{classname}\n {desc}>'.format(
            module=__name__,
            classname=self.__class__.__name__,
            desc='\n '.join(
                '{}={}'.format(
                    attr,
                    ('\n  '+' '*len(attr)).join(filter(bool, str(getattr(self, attr, None)).split('\n'))))
                for attr in ('command', 'path', 'headers')))


channels = {}
default_dispatcher = rpc_interface.create_dispatcher()
response_futures = collections.OrderedDict()


async def json_lines_with_timeout(reader: asyncio.StreamReader, timeout: 'seconds' = DEFAULT_TIMEOUT):
    while not reader.at_eof():
        line = await asyncio.wait_for(reader.readline(), timeout)
        try:
            yield json.loads(line)
        except json.JSONDecodeError as e:
            pass


async def establish_channel(eth_address: int,
                            reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter,
                            location: (str, int) = None):
    if eth_address not in channels:
        channels[eth_address] = {}

    if 'writer' in channels[eth_address]:
        logging.debug('channel for {:040x} already exists; reestablishing channel...'.format(eth_address))
        channels[eth_address]['writer'].close()
    else:
        logging.info('establishing new channel for {:040x}'.format(eth_address))

    channels[eth_address]['reader'] = reader
    channels[eth_address]['writer'] = writer
    channels[eth_address]['rpcdispatcher'] = rpc_interface.create_dispatcher(eth_address)
    if location is not None:
        channels[eth_address]['location'] = location

    try:
        async for msg in json_lines_with_timeout(reader):
            logging.debug('received message {} from {:040x}'.format(msg, eth_address))
            if msg is None:
                logging.warning('message should not be None!')
            elif 'method' in msg:
                res = JSONRPCResponseManager.handle(json.dumps(msg), channels[eth_address]['rpcdispatcher'])
                if res is not None:
                    res_data = await get_response_data(res)
                    res_str = json.dumps(res_data)
                    logging.debug('sending response {}'.format(res_str))
                    writer.write(res_str.encode())
                    writer.write(b'\n')
            elif 'id' in msg:
                fut_id = msg['id']
                if fut_id in response_futures:
                    response_future = response_futures.pop(fut_id)
                    if 'result' in msg:
                        response_future.set_result(msg['result'])
                    elif 'error' in msg:
                        response_future.set_exception(msg['error'])
                    else:
                        response_future.cancel()
                else:
                    logging.warning('Response with id {} has no corresponding future'.format(fut_id))
    except asyncio.TimeoutError:
        logging.warn('channel for {:040x} timed out'.format(eth_address))
    finally:
        writer.close()
        if writer is channels[eth_address].get('writer'):
            logging.info('removing channel for {:040x}'.format(eth_address))
            del channels[eth_address]['reader']
            del channels[eth_address]['writer']


def make_jsonrpc_call(cinfo: 'channel info',
                      method_name: str, *args,
                      is_notification: bool = False,
                      loop: asyncio.AbstractEventLoop = None):
    if loop is None:
        loop = asyncio.get_event_loop()

    msg = {
        'method': method_name,
        'params': args,
        'jsonrpc': '2.0',
    }

    if 'writer' in cinfo:
        if not is_notification:
            reqid = str(uuid.uuid4())
            msg['id'] = reqid
            response_futures[reqid] = asyncio.Future(loop=loop)

        writer = cinfo['writer']
        msg_str = json.dumps(msg)
        logging.debug('sending message: {}'.format(msg_str))
        writer.write(msg_str.encode())
        writer.write(b'\n')

        if not is_notification:
            return response_futures[reqid]
    else:
        logging.warning('cannot send message {} because channel {} has no writer'.format(msg, cinfo))


async def get_response_data(res: 'jsonrpc response', timeout: 'seconds' = DEFAULT_TIMEOUT) -> dict:
    if res is not None:
        res_data = res.data
        if 'result' in res_data:
            if (asyncio.iscoroutine(res_data['result']) or isinstance(res_data['result'], asyncio.Future)):
                res_data['result'] = await asyncio.wait_for(res_data['result'], timeout)
        return res_data


async def broadcast_jsonrpc_call_on_all_channels(method_name: str, *args,
                                                 timeout: 'seconds' = DEFAULT_TIMEOUT,
                                                 is_notification: bool = False,
                                                 loop: asyncio.AbstractEventLoop = None) -> dict:
    res_futures = {}

    for addr, cinfo in channels.items():
        res_futures[addr] = make_jsonrpc_call(cinfo, method_name, *args,
                                              is_notification=is_notification,
                                              loop=loop)

    if is_notification:
        return

    await asyncio.wait(res_futures.values(), timeout=timeout)

    res = {}

    for addr, res_future in res_futures.items():
        if res_future.done():
            try:
                temp = res_future.result()
            except Exception as e:
                logging.error(e)
            else:
                res[addr] = temp

    return res


async def determine_address_via_nonce(reader: asyncio.StreamReader,
                                      writer: asyncio.StreamWriter,
                                      timeout: 'seconds' = DEFAULT_TIMEOUT) -> int:
    # TODO: Make a nonce registry for extra security
    nonce = util.random.randrange(2**256)
    noncebytes = nonce.to_bytes(32, byteorder='big')
    logging.debug('sending nonce {:064x}'.format(nonce))
    writer.write(nonce.to_bytes(32, byteorder='big'))

    rsv_bytes = await asyncio.wait_for(reader.read(65), timeout)
    signature = util.bytes_to_signature(rsv_bytes)
    logging.debug('received signature rsv ({:064x}, {:064x}, {:02x})'.format(*signature))

    try:
        address = util.address_from_message_and_signature(noncebytes, signature, hash=None)
    except ValueError as err:
        logging.debug('could not recover address: {}'.format(err))
        return None

    logging.debug('got address: {:040x}'.format(address))
    return address


async def respond_to_nonce_with_signature(reader: asyncio.StreamReader,
                                          writer: asyncio.StreamWriter,
                                          timeout: 'seconds' = DEFAULT_TIMEOUT):
    noncebytes = await asyncio.wait_for(reader.read(32), timeout)
    nonce = int.from_bytes(noncebytes, byteorder='big')
    logging.debug('got nonce: {:064x}'.format(nonce))

    signature = util.sign_with_key(noncebytes, ecdkg.private_key, hash=None)
    logging.debug('sending nonce signature rsv ({:064x}, {:064x}, {:02x})'.format(*signature))
    writer.write(util.signature_to_bytes(signature))


################################################################################

async def emit_heartbeats():
    while True:
        for addr, cinfo in channels.items():
            if 'writer' in cinfo:
                cinfo['writer'].write(b'\n')
        await asyncio.sleep(HEARTBEAT_INTERVAL)


################################################################################

async def server(host: str, port: int, *,
                 timeout: 'seconds' = DEFAULT_TIMEOUT,
                 loop: asyncio.AbstractEventLoop):

    async def handle_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            cliipaddr = writer.get_extra_info('peername')
            ownipaddr = writer.get_extra_info('sockname')
            logging.debug('{} <-- {}'.format(ownipaddr, cliipaddr))

            protocol_indicator = await asyncio.wait_for(reader.read(4), timeout)

            if protocol_indicator == b'DKG ':
                await respond_to_nonce_with_signature(reader, writer, timeout)
                cliethaddr = await determine_address_via_nonce(reader, writer, timeout)

                if cliethaddr is None:
                    logging.debug('(s) could not verify client signature; closing connection')
                    return

                if cliethaddr not in ecdkg.accepted_addresses:
                    logging.debug('(s) client address {:40x} not accepted'.format(cliethaddr))
                    return

                await establish_channel(cliethaddr, reader, writer)

            elif len(protocol_indicator) > 0:
                req = HTTPRequest(protocol_indicator + await asyncio.wait_for(reader.readline(), timeout), reader)
                contentlen = req.headers.get('Content-Length')
                if contentlen is not None:
                    contentlen = int(contentlen)
                    req.body = await reader.read(contentlen)

                res = JSONRPCResponseManager.handle(req.body, default_dispatcher)
                res_data = await get_response_data(res, timeout)
                db.Session.remove()

                if res_data is None:
                    writer.write(b'HTTP/1.1 204 No Content\r\n\r\n')
                else:
                    res_str = json.dumps(res_data, indent=2, sort_keys=True).encode('UTF-8')

                    writer.write(b'HTTP/1.1 200 OK\r\n'
                                 b'Content-Type: application/json; charset=UTF-8\r\n'
                                 b'Content-Length: ')
                    writer.write(str(len(res_str) + 1).encode('UTF-8'))
                    writer.write(b'\r\n\r\n')
                    writer.write(res_str)
                    writer.write(b'\n')
        finally:
            writer.close()

    logging.debug('(s) serving on {}:{}'.format(host, port))
    await asyncio.start_server(handle_connection,
                               host, port, loop=loop)


################################################################################

async def attempt_to_establish_channel(host: str, port: int, *,
                                       timeout: 'seconds' = DEFAULT_TIMEOUT,
                                       num_tries: int = 6):

    logging.debug('(c) attempting to connect to {}:{}'.format(host, port))
    for i in range(num_tries):
        try:
            reader, writer = await asyncio.open_connection(host, port)
        except OSError as e:
            if e.errno == 111 or '[Errno 111]' in str(e):  # connection refused
                if i < num_tries - 1:
                    wait_time = 5 * 2**i
                    logging.debug('(c) connection to {}:{} refused; trying again in {}s'.format(host, port, wait_time))
                    await asyncio.sleep(wait_time)
            else:
                raise
        else:
            srvipaddr = writer.get_extra_info('peername')
            ownipaddr = writer.get_extra_info('sockname')
            logging.debug('{} --> {}'.format(ownipaddr, srvipaddr))
            break
    else:
        logging.warning('could not connect to {}:{} after {} tries'.format(host, port, num_tries))
        return

    try:
        writer.write(b'DKG ')

        srvethaddr = await determine_address_via_nonce(reader, writer, timeout)

        if srvethaddr is None:
            logging.info('(c) could not determine server address; closing connection...')
            return

        if srvethaddr not in ecdkg.accepted_addresses:
            logging.debug('(c) server eth address {:040x} not accepted'.format(srvethaddr))
            return

        if srvethaddr in channels and 'writer' in channels[srvethaddr]:
            logging.info('(c) already connected to {:040x}; ending connection attempt'.format(srvethaddr))
            return

        await respond_to_nonce_with_signature(reader, writer, timeout)

        await establish_channel(srvethaddr, reader, writer, srvipaddr)
    finally:
        writer.close()
