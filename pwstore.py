#!/usr/bin/env python3
"""
   pwstore
   ~~~~~~~

   A commandline-based secure password storage system.

   :copyright: 2018 by Kharidiron
   :license: MIT

"""

__version__ = '1.0'

import argparse
import base64
import cmd
import datetime
import getpass
import hashlib
import logging
import shelve
import shlex
import sys


# custom log level, for when I need MOAR VERBOSE
DEBUGV = 5
logging.addLevelName(DEBUGV, 'VERBOSE')

# current log level
LEVEL = logging.INFO

# globals
DB = 'pwstore.db'
MASTER = None


class Prompt(cmd.Cmd):
    """Prompt mode. So one doesn't have to keep typing the master password."""

    intro = ('Password Store - console mode\n'
             'Type help or ? for a list of commands.\n')
    prompt = '(pwstore) '

    def __init__(self, parser):
        super(Prompt, self).__init__()
        self.parser = parser

    def default(self, args):
        print('Error: command not recognized.')
        return

    def do_add(self, args):
        'Add an entry to the store.'
        arg_list = list(shlex.split(args))
        arg_list.insert(0, 'add')
        print(arg_list)

        try:
            argp = self.parser.parse_args(arg_list)
            pws_add(argp)
        except SystemExit:
            pass

    def do_remove(self, args):
        'Remove an entry from the store.'
        arg_list = list(shlex.split(args))
        arg_list.insert(0, 'remove')

        try:
            argp = self.parser.parse_args(arg_list)
            pws_remove(argp)
        except SystemExit:
            pass

    def do_update(self, args):
        'Update an entry in the store.'
        arg_list = list(shlex.split(args))
        arg_list.insert(0, 'update')

        try:
            argp = self.parser.parse_args(arg_list)
            pws_update(argp)
        except SystemExit:
            pass

    def do_get(self, args):
        'Get an entry from the store.'
        arg_list = list(shlex.split(args))
        arg_list.insert(0, 'get')

        try:
            argp = self.parser.parse_args(arg_list)
            pws_get(argp)
        except SystemExit:
            pass

    def do_list(self, args):
        'List all entries in the store.'
        arg_list = list(shlex.split(args))
        arg_list.insert(0, 'list')

        try:
            argp = self.parser.parse_args(arg_list)
            pws_list(argp)
        except SystemExit:
            pass

    def do_exit(self, args):
        self.do_quit(args)

    def do_quit(self, args):
        'Quit this console.'
        print('Quitting.')
        raise SystemExit


def pw_encode(key, clear):
    """Vigenère cipher encoder.

    Lifted from here: https://stackoverflow.com/a/38223403"""

    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)

    return base64.urlsafe_b64encode(''.join(enc).encode()).decode()


def pw_decode(key, enc):
    """Vigenère cipher decoder.

    Lifted from here: https://stackoverflow.com/a/38223403

    :return: string
    """

    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)

    return ''.join(dec)


def initialize_logger():
    """Initialize logging for debugging.

    :return: logging object
    """

    logger = logging.getLogger()
    logger.setLevel(LEVEL)

    if not logger.handlers:
        logger.propagate = 0
        console = logging.StreamHandler()
        logger.addHandler(console)

        format_string = '%(asctime)s - %(levelname)s - %(message)s'
        formatter = logging.Formatter(format_string)
        console.setFormatter(formatter)

    return logger


def initialize_cli_parser():
    """Initializes function to parse command-line input.

    :return: ArgumentParser object
    """

    logging.debug('initializing parser')

    # core parser
    parser = argparse.ArgumentParser(prog='pwstore',
                                     description='Secure password storage.')
    subparse = parser.add_subparsers()

    # add entry subparser
    subcmd_add = subparse.add_parser('add',
                                     help='Add an entry to the store.')
    subcmd_add.add_argument('context', help='Context for entry.')
    subcmd_add.add_argument('username', help='Username.')
    subcmd_add.add_argument('-n', '--note', help='Notes.')
    subcmd_add.set_defaults(func=pws_add)

    # remove entry subparser
    subcmd_remove = subparse.add_parser('remove',
                                        help='Remove an entry from the store.')
    subcmd_remove.add_argument('context', help='Context for entry.')
    subcmd_remove.add_argument('--username', help='Username (if needed).')
    subcmd_remove.set_defaults(func=pws_remove)

    # update entry subparser
    subcmd_update = subparse.add_parser('update',
                                        help='Update an entry in the store.')
    subcmd_update.add_argument('context', help='Context for entry.')
    subcmd_update.add_argument('--username', help='Current Username.')
    subcmd_update.add_argument('-u', '--new_username', help='Update username.')
    subcmd_update.add_argument('-p', '--new_password', help='Update password.')
    subcmd_update.add_argument('-n', '--new_note', help='Update Notes.')
    subcmd_update.set_defaults(func=pws_update)

    # get an entry from storage
    subcmd_get = subparse.add_parser('get',
                                     help='Retrieve an entry from the store.')
    subcmd_get.add_argument('context', help='Context for entry.')
    subcmd_get.set_defaults(func=pws_get)

    # list all entries in storage
    subcmd_list = subparse.add_parser('list',
                                      help='List all entries in the store.')
    subcmd_list.add_argument('--force', required=True, action='store_true')
    subcmd_list.set_defaults(func=pws_list)

    # shred all storage
    subcmd_shred = subparse.add_parser('shred',
                                       help='Shred all entries in the store.')
    subcmd_shred.add_argument('--force', required=True, action='store_true')
    subcmd_shred.set_defaults(func=pws_shred)

    return parser


def initialize_storge():
    """Check for a database and try to load it.

    If ones doesn't already exist, create it. Afterwards, get the master
    password for reading the database from the user.

    :return: None
    """

    with shelve.open(DB) as s:
        try:
            # Check if a serial number exists.
            __ = s['_serial']
            del __
        except KeyError:
            # Initialize the DB if it doesn't
            s['_serial'] = 1
            logging.debug('database initialized')
        except Exception as e:
            logging.critical('Exception: {}'.format(e))
            raise SystemExit

    # Get the master password. Keep it around until we exit
    global MASTER
    if not MASTER:
        M = hashlib.sha256()
        M.update(bytes(getpass.getpass(prompt='Master password: '),
                       encoding='utf-8'))
        MASTER = M.hexdigest()

    return


class Entry:
    """ Password entry prototype
    """

    context = ''
    username = ''
    password = ''
    note = ''
    date_added = None
    last_updated = None

    def __init__(self, context='', username='', password='', **kwargs):
        self.context = context
        self.username = username
        self.password = password
        self.note = str(kwargs.get('note', ''))
        self.date_added = datetime.datetime.now()
        self.last_updated = datetime.datetime.now()


def pw_pprint(keylist):
    """Pretty-print entries in the console.

    :return: None
    """

    # column widths
    cols = [14, 14, 14, 20]

    def _sep(cols):
        # helper function for printing nice horizontal lines
        print('|-{}-|-{}-|-{}-|-{}-|'.format(''.ljust(cols[0], '-'),
                                             ''.ljust(cols[1], '-'),
                                             ''.ljust(cols[2], '-'),
                                             ''.ljust(cols[3], '-')))

    # do nothing if there is nothing to be printed
    if not keylist:
        return

    with shelve.open(DB) as s:
        _sep(cols)
        print('| {} | {} | {} | {} |'.format('context'.center(cols[0]),
                                             'username'.center(cols[1]),
                                             'password'.center(cols[2]),
                                             'notes'.center(cols[3])))
        _sep(cols)
        for k in keylist:
            d = {'c': pw_decode(MASTER, s[k].context).ljust(cols[0]),
                 'u': pw_decode(MASTER, s[k].username).ljust(cols[1]),
                 'p': pw_decode(MASTER, s[k].password).ljust(cols[2]),
                 'n': pw_decode(MASTER, s[k].note).ljust(cols[3])}
            print('| {c} | {u} | {p} | {n} |'.format(**d))
        _sep(cols)

    return


def pws_add(args):
    """Add entry to storage.
    """

    logging.debug('in add command')

    # generate the current key we want to work with
    ctx = '_{}_{}__'.format(args.context, args.username)

    with shelve.open(DB) as s:
        # get a list of all the keys in storage
        keylist = list(s.keys())
        logging.log(DEBUGV, 'keylist: {}'.format(keylist))
        keylist.remove('_serial')

        # check if it is already in the database
        res = [key for key in keylist
               if ctx.lower() in pw_decode(MASTER, key).lower()]

        if len(res):
            logging.debug('Context already in use. Aborting')
            print('Cannot add - this pattern already exists. Did you mean '
                  'to update instead?')
        else:
            logging.debug('unused context')

            # builds the entry. prompts user for password
            entry = Entry(context=pw_encode(MASTER, args.context),
                          username=pw_encode(MASTER, args.username),
                          password=pw_encode(MASTER, getpass.getpass()),
                          note=pw_encode(MASTER, str(args.note)))

            logging.log(DEBUGV, entry)

            # create entry key and stores it
            key = pw_encode(MASTER, '{}_{}__'.format(s['_serial'], ctx))
            s[key] = entry
            print('Entry added.')

            # advance the serial number
            s['_serial'] = s['_serial'] + 1
            logging.debug('serial advanced')

    return


def pws_remove(args):
    """Remove entry from storage.
    """

    logging.debug('in remove command')

    # generate the current key we want to work with
    ctx = '_{}_'.format(args.context)
    if args.username:
        ctx = '_{}_{}__'.format(args.context, args.username)

    with shelve.open(DB) as s:
        # get a list of all the keys in storage
        keylist = list(s.keys())
        logging.log(DEBUGV, 'keylist: {}'.format(keylist))
        keylist.remove('_serial')

        # check if it is already in the database
        res = [key for key in keylist
               if ctx.lower() in pw_decode(MASTER, key).lower()]
        logging.log(DEBUGV, 'result: {}'.format(res))

        if len(res) > 1:
            print('More than one result found. You _must_ pass '
                  'the username option to update, in this case.')
            return
        elif len(res) == 0:
            print('No result found.')
            return
        else:
            del s[res[0]]
            print('Entry has been removed.')

    return


def pws_update(args):
    """Update entry in storage.
    """

    logging.debug('in update command')

    # generate the current key we want to work with
    ctx = '_{}_'.format(args.context)
    if args.username:
        ctx = '_{}_{}__'.format(args.context, args.username)

    with shelve.open(DB) as s:
        # get a list of all the keys in storage
        keylist = list(s.keys())
        logging.log(DEBUGV, 'keylist: {}'.format(keylist))
        keylist.remove('_serial')

        # check if it is already in the database
        res = [key for key in keylist
               if ctx.lower() in pw_decode(MASTER, key).lower()]
        logging.log(DEBUGV, 'result: {}'.format(res))

        if len(res) > 1:
            print('More than one entry found. You _must_ pass the '
                  'username option to update, in this case.')
            return
        elif len(res) == 0:
            print('No entry found for that context.')
            return
        else:
            entry = s[res[0]]

            if args.new_username:
                entry.username = pw_encode(MASTER, args.new_username)

            if args.new_note:
                entry.note = pw_encode(MASTER, args.new_note)

            if args.new_password:
                entry.password = pw_encode(MASTER, getpass.getpass())

            entry.last_updated = datetime.datetime.now()

            s[res[0]] = entry
            print('Entry updated.')

    return


def pws_get(args):
    """Get entry from storage.
    """

    logging.debug('in get command')

    with shelve.open(DB) as s:
        keylist = list(s.keys())
        logging.log(DEBUGV, 'keylist: {}'.format(keylist))
        keylist.remove('_serial')

        ctx = '_{}_'.format(args.context)
        res = [key for key in keylist
               if ctx.lower() in pw_decode(MASTER, key).lower()]
        if len(res) == 0:
            print('No results were found.')
            return

    pw_pprint(res)

    return


def pws_list(args):
    """List all entries in storage.
    """

    logging.debug('in list command')

    keylist = None
    with shelve.open(DB) as s:
        keylist = list(s.keys())
        keylist.remove('_serial')
    pw_pprint(keylist)

    return


def pws_shred(args):
    """Shred storage (destroys all entries).
    """

    logging.debug('in shred command')

    raise NotImplemented

    return


def main(argv):
    logger = initialize_logger()
    logger.debug('argv: {}'.format(argv))

    parser = initialize_cli_parser()

    initialize_storge()

    if len(argv) == 0:
        logger.debug('starting console mode.')
        prompt = Prompt(parser=parser)
        prompt.cmdloop()

    args = parser.parse_args(argv)
    args.func(args)

    global MASTER
    del MASTER

    return


if __name__ == '__main__':
    main(sys.argv[1:])
