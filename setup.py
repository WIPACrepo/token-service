import sys
from setuptools import setup
from os import path

import token_service

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md')) as f:
    long_description = f.read()


install_requires = ['tornado>=5.1', 'pymongo>=3.7', 'PyJWT']
if sys.version_info < (3, 3):
    raise Exception('only python 3')

setup(
    name='token_service',
    version=token_service.__version__,
    description='File catalog',
    long_description=long_description,
    url='https://github.com/WIPACrepo/token-service',
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
    ],
    keywords='token service',
    packages=['token_service'],
    install_requires=install_requires,
    package_data={
        'token_service':['static/*','templates/*'],
    },
)
