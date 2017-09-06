from setuptools import setup
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='pydkg',
    version='0.1.0.dev1',
    description='Distributed key generation',
    long_description=long_description,
    url='http://github.com/gnosis/pydkg',
    author='Alan Lu',
    author_email='alan.lu@gnosis.pm',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',

        'Environment :: No Input/Output (Daemon)',

        'Intended Audience :: Developers',
        'Intended Audience :: Science/Research',

        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
    ],

    packages=['pydkg'],
    install_requires=[
        'cryptography',
        'json-rpc',
        'py_ecc',
        'python-dateutil',
        'sqlalchemy',
    ],
    extras_require={
        'test': [
            'flake8',
            'populus',
            'psutil',
            'pytest',
            'requests',
        ],
    },

    entry_points={
        'console_scripts': [
            'pydkg=pydkg.__main__:main',
        ],
    },
)
