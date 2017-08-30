import pytest


def pytest_addoption(parser):
    parser.addoption("--num-ecdkg-nodes", action="store", default=5, type=int,
        help="number of ecdkg nodes %(default)s")
    parser.addoption("--request-timeout", action="store", default=5, type=float,
        help="request timeout %(default)s")


@pytest.fixture
def num_ecdkg_nodes(request):
    return request.config.getoption("--num-ecdkg-nodes")


@pytest.fixture
def request_timeout(request):
    return request.config.getoption("--request-timeout")
