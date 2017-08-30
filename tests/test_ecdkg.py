import collections
import functools
import json
import logging
import os
import requests
import signal
import subprocess
import tempfile
import time

from contextlib import ExitStack, contextmanager
from datetime import datetime

from py_ecc.secp256k1 import secp256k1
import psutil
import pytest

from pydkg import util


BIN_NAME = 'gnodex'
PORTS_START = 59828

NodeInfo = collections.namedtuple('NodeInfo', (
    'process',
    'private_key',
    'port',
))


@contextmanager
def Popen_with_interrupt_at_exit(cmdargs, *args, **kwargs):
    p = None
    try:
        p = psutil.Popen(cmdargs, *args, **kwargs)
        yield p
    finally:
        if p is not None:
            # start by trying to end process gently, but escalate
            for endfn in (functools.partial(p.send_signal, signal.SIGINT), p.terminate, p.kill):
                if p.poll() is None:
                    endfn()
                    try:
                        # TODO: switch to asyncio???
                        p.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        continue

@pytest.fixture
def nodes(num_ecdkg_nodes, request_timeout):
    subprocess.check_call((BIN_NAME, '-h'), stdout=subprocess.DEVNULL)
    with ExitStack() as exitstack:
        proc_dir = exitstack.enter_context(tempfile.TemporaryDirectory())
        proc_dir_file = functools.partial(os.path.join, proc_dir)

        private_keys = tuple(util.get_or_generate_private_value(
            proc_dir_file('private.key.{}'.format(i)))
            for i in range(num_ecdkg_nodes))

        with open(proc_dir_file('addresses.txt'), 'w') as addrf:
            for privkey in private_keys:
                addrf.write("{:040x}\n".format(util.private_value_to_eth_address(privkey)))

        with open(proc_dir_file('locations.txt'), 'w') as locf:
            for i in range(num_ecdkg_nodes):
                locf.write("localhost:{}\n".format(PORTS_START+i))

        processes = []
        for i in range(num_ecdkg_nodes):
            processes.append(exitstack.enter_context(Popen_with_interrupt_at_exit((
                BIN_NAME, 'ecdkg',
                '--port', str(PORTS_START+i),
                '--private-key-file', proc_dir_file('private.key.{}'.format(i)),
                '--addresses-file', proc_dir_file('addresses.txt'),
                '--locations', proc_dir_file('locations.txt'),
                '--log-level', str(logging.DEBUG),
                '--log-format', '[{}]: %(message)s'.format(i),
            ))))
            # TODO: Figure out why channels randomly do not get set up with tighter timing
            time.sleep(0.1)

        yield tuple(NodeInfo(process=proc, private_key=privkey, port=PORTS_START+i) for i, (proc, privkey) in enumerate(zip(processes, private_keys)))


def is_node_listening(node: NodeInfo):
    return any(True for con in node.process.connections() if con.status == psutil.CONN_LISTEN)


def wait_for_all_nodes_listening(nodes, timeout):
    # TODO: Do something better than spinlock maybe?
    #       This could maybe be improved if transitioning to an asyncio version
    #       but then would lose psutil interop
    timelimit = time.perf_counter() + timeout

    while any(not is_node_listening(n) for n in nodes):
        if time.perf_counter() >= timelimit:
            print('wait_for_all_nodes_listening took longer than {} seconds'.format(timeout))
            print_diagnostics(nodes)
            break


def wait_for_all_nodes_connected(nodes, timeout):
    # each node connects to each other node
    timelimit = time.perf_counter() + timeout

    while any(sum(1 for con in n.process.connections() if con.status == psutil.CONN_ESTABLISHED) != len(nodes)-1 for n in nodes):
        if time.perf_counter() >= timelimit:
            print('wait_for_all_nodes_connected took longer than {} seconds'.format(timeout))
            print_diagnostics(nodes)
            break

    time.sleep(.1) # TODO: remove requirement for waiting for channel establishment


def print_diagnostics(nodes):
    portmap = {}
    node_conns = [[c for c in n.process.connections() if c.status == psutil.CONN_ESTABLISHED] for n in nodes]
    for i, (n, conns) in enumerate(zip(nodes, node_conns)):
        for c in conns:
            portmap[c.laddr[1]] = i

    node_conn_sets = []
    unestablished_connections = set()
    for i, (n, conns) in enumerate(zip(nodes, node_conns)):
        outset = set()
        inset = set()

        for c in conns:
            if c.laddr[1] == n.port:
                inset.add(portmap.get(c.raddr[1], -1))
            else:
                outset.add(portmap.get(c.raddr[1], -1))

        node_conn_sets.append((sorted(inset), sorted(outset)))
        for elem in range(len(nodes)):
            if i != elem and elem not in inset and elem not in outset:
                unestablished_connections.add(tuple(sorted((i, elem))))

    for i, (n, conns, (ins, outs)) in enumerate(zip(nodes, node_conns, node_conn_sets)):
        print(i, '- num connections:', len(conns))
        print('  - out', outs)
        print('  - in ', ins)

    for a, b in sorted(unestablished_connections):
        print(a, '-X-', b)


def test_nodes_match_state(nodes, request_timeout):
    wait_for_all_nodes_listening(nodes, request_timeout)

    deccond = 'past {}'.format(datetime.utcnow().isoformat())
    responses = [requests.post('https://localhost:{}'.format(n.port),
        verify=False,
        timeout=request_timeout,
        data=json.dumps({
            'id': 'honk',
            'method': 'get_ecdkg_state',
            'params': [deccond],
        })).json()['result'] for n in nodes]

    assert(all(r['decryption_condition'] == responses[0]['decryption_condition'] for r in responses[1:]))


def test_nodes_match_enckey_and_deckeys(nodes, request_timeout):
    wait_for_all_nodes_connected(nodes, request_timeout)

    deccond = 'past {}'.format(datetime.utcnow().isoformat())
    enckeys = [requests.post('https://localhost:{}'.format(n.port),
        verify=False,
        timeout=request_timeout,
        data=json.dumps({
            'id': 'honk',
            'method': 'get_encryption_key',
            'params': [deccond],
        })).json()['result'] for n in nodes]

    enckeys = [tuple(int(ek[i:i+64], 16) for i in (0, 64)) for ek in enckeys]

    for ek in enckeys:
        util.validate_curve_point(ek)

    assert(all(ek == enckeys[0] for ek in enckeys[1:]))

    deckeys = [requests.post('https://localhost:{}'.format(n.port),
        verify=False,
        timeout=request_timeout,
        data=json.dumps({
            'id': 'honk',
            'method': 'get_decryption_key',
            'params': [deccond],
        })).json()['result'] for n in nodes]

    deckeys = [int(dk, 16) for dk in deckeys]

    for dk in deckeys:
        util.validate_private_value(dk)

    assert(all(dk == deckeys[0] for dk in deckeys[1:]))

    assert(secp256k1.multiply(secp256k1.G, deckeys[0]) == enckeys[0])
