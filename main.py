#!/usr/bin/env python3

import argparse

from testcases import roq_interop_test
from network.network import setup, clean, setup_tc, clear_tc


def roq_interop_test_cmd(args):
    roq_interop_test()

def setup_cmd(args):
    setup()


def clean_cmd(args):
    clean()


def setup_tc_cmd(args):
    setup_tc()


def clear_tc_cmd(args):
    clear_tc()


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    subparsers = parser.add_subparsers(help='sub-command help', required=True)

    clean = subparsers.add_parser('clean', help='clean up virtual interaces and namespaces')
    clean.set_defaults(func=clean_cmd)

    setup = subparsers.add_parser('setup', help='setup virtual interfaces and namespaces')
    setup.set_defaults(func=setup_cmd)

    setup_tc = subparsers.add_parser('tc', help='add netem delay qdisc')
    setup_tc.set_defaults(func=setup_tc_cmd)

    clean_tc = subparsers.add_parser('clear', help='remove any tc qdiscs')
    clean_tc.set_defaults(func=clear_tc_cmd)

    roq_interop = subparsers.add_parser('roq', help='run RoQ interop test')
    roq_interop.set_defaults(func=roq_interop_test_cmd)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

