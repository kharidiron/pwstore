#!/usr/bin/env python3
"""
   pwstore
   ~~~~~~~

   A commandline-based secure password storage system.

   :copyright: 2018 by Kharidiron
   :license: I'll decide this later.

"""

__version__ = '0.1-dev'

import argparse
import base64
import cmd
import datetime
# import getpass
import logging
import shelve
import sys


DB = 'pwstore.db'
DEBUGV = 5
logging.addLevelName(DEBUGV, 'VERBOSE')
LEVEL = logging.DEBUG


class Prompt(cmd.Cmd):
    intro = ('Password Store - console mode\n'
             'Type help or ? for a list of commands.\n')
    prompt = '(pwstore) '

    def default(self, args):
        print('Error: command not recognized.')
        return None

    def do_add(self, args):
        'Add an entry to the store.'
        if len(args) == 0:
            print('usage goes here')
            return
        pws_add(args)

    def do_remove(self, args):
        'Remove an entry from the store.'
        if len(args) == 0:
            print('usage goes here')
            return
        pws_remove(args)

    def do_update(self, args):
        'Update an entry in the store.'
        if len(args) == 0:
            print('usage goes here')
            return
        pws_update(args)

    def do_get(self, args):
        'Get an entry from the store.'
        if len(args) == 0:
            print('usage goes here')
            return
        pws_get(args)

    def do_list(self, args):
        'List all entries in the store.'
        if len(args) == 0:
            print('usage goes here')
            return
        pws_list(args)

    def do_exit(self, args):
        self.do_quit(args)

    def do_quit(self, args):
        'Quit this console.'
        print('Quitting.')
        raise SystemExit


def pw_encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)

    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def pw_decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)

    return "".join(dec)


def initialize_logger():
    """Initialize logging for debugging.
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


def initialize_parser():
    """Initializes function to parse command-line input.

    :return: ArgumentParser object.
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
    subcmd_remove.set_defaults(func=pws_remove)

    # update entry subparser
    subcmd_update = subparse.add_parser('update',
                                        help='Update an entry in the store.')
    subcmd_update.add_argument('context', help='Context for entry.')
    subcmd_update.add_argument('-u', '--username', help='Update username.')
    subcmd_update.add_argument('-p', '--password', help='Update password.')
    subcmd_update.add_argument('-n', '--note', help='Update Notes.')
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
    with shelve.open(DB) as s:
        try:
            _ = s['_serial']
        except KeyError:
            s['_serial'] = 1
            logging.debug('database initialized')
        except Exception as e:
            logging.critical('Exception: {}'.format(e))
            raise SystemExit

    return None


class Entry:
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
        self.note = kwargs.get('note', '')
        self.last_updated = datetime.datetime.now()

    def __eq__(self, other):
        return isinstance(other, Entry)

    def __repr__(self):
        return ('<Entry(context={}, username={}, note={}, last_updated={})>'
                ''.format(self.context,
                          self.username,
                          self.note,
                          self.last_updated))


def pws_add(args):
    """Add entry to storage."""
    logging.debug('in add command')
    logging.log(DEBUGV, 'add args: {}'.format(args))

    with shelve.open(DB) as s:
        # get a list of all the keys in storage
        keylist = list(s.keys())
        logging.log(DEBUGV, 'keylist: {}'.format(keylist))

        # generate the current key we want to work with
        ctx = '{}_{}'.format(args.context, args.username)

        # check if it is already in the database
        res = list(filter(lambda x: x.endswith(ctx), keylist))

        if len(res):
            logging.warning('Context already in use.')
        else:
            logging.debug('unused context')

            entry = Entry(context=args.context,
                          username=args.username,
                          password='',
                          note=args.note)

            logging.log(DEBUGV, entry)

            key = '{}_{}'.format(s['_serial'], ctx)
            s[key] = entry

            logging.info('Entry added.')

            s['_serial'] = s['_serial'] + 1
            logging.debug('serial advanced')

    return None


def pws_remove(args):
    """Remove entry from storage."""
    logging.debug('in remove command')

    return None


def pws_update(args):
    """Update entry in storage."""
    logging.debug('in update command')

    return None


def pws_get(args):
    """Get entry from storage."""
    logging.debug('in get command')

    return None


def pws_list(args):
    """List all entries in storage."""
    logging.debug('in list command')

    cols = [14, 14, 14, 20]

    def _sep(cols):
        print('|-{}-|-{}-|-{}-|-{}-|'.format(''.ljust(cols[0], '-'),
                                             ''.ljust(cols[1], '-'),
                                             ''.ljust(cols[2], '-'),
                                             ''.ljust(cols[3], '-')))

    with shelve.open(DB) as s:
        _sep(cols)
        print('| {} | {} | {} | {} |'.format('context'.center(cols[0]),
                                             'username'.center(cols[1]),
                                             'password'.center(cols[2]),
                                             'notes'.center(cols[3])))
        _sep(cols)
        keylist = list(s.keys())
        keylist.remove('_serial')
        for k in keylist:
            print('| {} | {} | {} | {} |'.format(s[k].context.ljust(cols[0]),
                                                 s[k].username.ljust(cols[1]),
                                                 ''.ljust(cols[2]),
                                                 str(s[k].note).ljust(cols[3])))
        _sep(cols)

    return None


def pws_shred(args):
    """Shred storage (destroys all entries)"""
    logging.debug('in shred command')

    return None


def main(argv):
    logger = initialize_logger()
    logger.debug('argv: {}'.format(argv))

    parser = initialize_parser()

    initialize_storge()

    if len(argv) == 0:
        logger.debug('starting console mode.')
        prompt = Prompt()
        prompt.cmdloop()

    args = parser.parse_args(argv)
    args.func(args)
    logger.log(DEBUGV, 'args: {}'.format(args))

    logger.debug('end of line.')

    return None


if __name__ == '__main__':
    main(sys.argv[1:])
