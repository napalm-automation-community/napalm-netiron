"""setup.py file."""

import uuid

from setuptools import setup, find_packages

__author__ = 'Bryan Lynn <blynn@llnw.com>'

with open('requirements.txt') as f:
    install_requires = f.read().strip().splitlines()

setup(
    name="napalm-netiron",
    version="0.1.6",
    packages=find_packages(),
    author="Bryan Lynn",
    author_email="blynn@llnw.com",
    description="Network Automation and Programmability Abstraction Layer with Multivendor support",
    classifiers=[
        'Topic :: Utilities',
         'Programming Language :: Python',
         'Programming Language :: Python :: 2',
         'Programming Language :: Python :: 2.7',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
    ],
    url="https://github.com/napalm-automation/napalm-netiron",
    include_package_data=True,
    install_requires=install_requires,
)
