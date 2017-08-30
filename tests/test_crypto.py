import os
from py_ecc.secp256k1 import secp256k1
from pydkg import util, crypto


def test_can_decrypt_encrypted_random_messages(chain):
    # TODO: Fix populus compat
    ies, _ = chain.provider.get_or_deploy_contract('IntegratedEncryptionScheme')
    num_runs = 10
    average_gas_cost = 0
    for _ in range(num_runs):
        message = os.urandom(util.random.randrange(1, 100))
        deckey = util.random_private_value()
        enckey = secp256k1.multiply(secp256k1.G, deckey)
        ciphertext = crypto.encrypt(message, enckey)
        assert message == crypto.decrypt(ciphertext, deckey)
        assert crypto.decrypt(ciphertext, deckey, foo=True) == ies.call().decrypt(ciphertext, deckey)
        average_gas_cost += ies.estimateGas().decrypt(ciphertext, deckey)

    average_gas_cost /= num_runs
    # assert average_gas_cost == 0
