#!/usr/bin/env python
# -*- coding: utf-8 -*-

import io
from setuptools import setup


with io.open('README.rst', 'rt', encoding='utf8') as f:
    readme = f.read()


setup(
    name='pwstore',
    version='1.0',
    url='',
    license='MIT',
    author='Kharidiron',
    author_email='kharidiron@gmail.com',
    description='A simple commandline password management tool.',
    long_description=readme,
    packages=['pwstore'],
    include_package_data=True,
    zip_safe=False,
    platforms='any',
    install_requires=[],
    extras_require={
        'dev': [
            'pytest>=3',
            'coverage',
            'tox',
            'sphinx',
        ],
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Security',
        'Topic :: Utilities',
    ],
)
