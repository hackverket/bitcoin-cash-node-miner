#!/usr/bin/env python3
# Copyright (c) 2017-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test getblockstats rpc call
#
import decimal
import json
import os
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

TESTSDIR = os.path.dirname(os.path.realpath(__file__))


def EncodeDecimal(o):
    if isinstance(o, decimal.Decimal):
        # json.load will read a quoted float as a string and not convert it back
        # to decimal, so store the value as unquoted float instead.
        return float(o)
    raise TypeError(repr(o) + " is not JSON serializable")


class GetblockstatsTest(BitcoinTestFramework):

    start_height = 101
    max_stat_pos = 2
    STATS_NEED_TXINDEX = [
        'avgfee',
        'avgfeerate',
        'maxfee',
        'maxfeerate',
        'medianfee',
        'feerate_percentiles',
        'minfee',
        'minfeerate',
        'totalfee',
        'utxo_size_inc',
    ]

    def add_options(self, parser):
        parser.add_argument('--gen-test-data', dest='gen_test_data',
                            default=False, action='store_true',
                            help='Generate test data')
        parser.add_argument('--test-data', dest='test_data',
                            default='data/rpc_getblockstats.json',
                            action='store', metavar='FILE',
                            help='Test data file')

    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [['-txindex'], ['-paytxfee=0.003']]
        self.setup_clean_chain = True

    def get_stats(self):
        return [self.nodes[0].getblockstats(
            hash_or_height=self.start_height + i) for i in range(self.max_stat_pos + 1)]

    def generate_test_data(self, filename):
        mocktime = time.time()
        self.nodes[0].generate(101)

        self.nodes[0].sendtoaddress(
            address=self.nodes[1].getnewaddress(), amount=10, subtractfeefromamount=True)
        self.nodes[0].generate(1)
        self.sync_all()

        self.nodes[0].sendtoaddress(
            address=self.nodes[0].getnewaddress(), amount=10, subtractfeefromamount=True)
        self.nodes[0].sendtoaddress(
            address=self.nodes[0].getnewaddress(), amount=10, subtractfeefromamount=False)
        self.nodes[1].sendtoaddress(
            address=self.nodes[0].getnewaddress(), amount=1, subtractfeefromamount=True)
        self.sync_all()
        self.nodes[0].generate(1)

        self.expected_stats = self.get_stats()

        blocks = []
        tip = self.nodes[0].getbestblockhash()
        blockhash = None
        height = 0
        while tip != blockhash:
            blockhash = self.nodes[0].getblockhash(height)
            blocks.append(self.nodes[0].getblock(blockhash, 0))
            height += 1

        to_dump = {
            'blocks': blocks,
            'mocktime': int(mocktime),
            'stats': self.expected_stats,
        }
        with open(filename, 'w', encoding="utf8") as f:
            json.dump(to_dump, f, sort_keys=True,
                      indent=2, default=EncodeDecimal)

    def load_test_data(self, filename):
        with open(filename, 'r', encoding="utf8") as f:
            d = json.load(f, parse_float=decimal.Decimal)
            blocks = d['blocks']
            mocktime = d['mocktime']
            self.expected_stats = d['stats']
            self.log.info(self.expected_stats)

        # Set the timestamps from the file so that the nodes can get out of
        # Initial Block Download
        self.nodes[0].setmocktime(mocktime)
        self.nodes[1].setmocktime(mocktime)

        for i, b in enumerate(blocks):
            self.nodes[0].submitblock(b)

    def run_test(self):
        test_data = os.path.join(TESTSDIR, self.options.test_data)
        if self.options.gen_test_data:
            self.generate_test_data(test_data)
        else:
            self.load_test_data(test_data)

        self.sync_all()
        stats = self.get_stats()
        expected_stats_noindex = []
        for stat_row in stats:
            expected_stats_noindex.append(
                {k: v for k, v in stat_row.items() if k not in self.STATS_NEED_TXINDEX})

        # Make sure all valid statistics are included but nothing else is
        expected_keys = self.expected_stats[0].keys()
        assert_equal(set(stats[0].keys()), set(expected_keys))

        assert_equal(stats[0]['height'], self.start_height)
        assert_equal(stats[self.max_stat_pos]['height'],
                     self.start_height + self.max_stat_pos)

        for i in range(self.max_stat_pos + 1):
            self.log.info('Checking block {}\n'.format(i))
            assert_equal(stats[i], self.expected_stats[i])

            # Check selecting block by hash too
            blockhash = self.expected_stats[i]['blockhash']
            stats_by_hash = self.nodes[0].getblockstats(
                hash_or_height=blockhash)
            assert_equal(stats_by_hash, self.expected_stats[i])

            # Check with the node that has no txindex
            stats_no_txindex = self.nodes[1].getblockstats(
                hash_or_height=blockhash, stats=list(expected_stats_noindex[i].keys()))
            assert_equal(stats_no_txindex, expected_stats_noindex[i])

        # Make sure each stat can be queried on its own
        for stat in expected_keys:
            for i in range(self.max_stat_pos + 1):
                result = self.nodes[0].getblockstats(
                    hash_or_height=self.start_height + i, stats=[stat])
                assert_equal(list(result.keys()), [stat])
                if result[stat] != self.expected_stats[i][stat]:
                    self.log.info('result[{}] ({}) failed, {!r} != {!r}'.format(
                        stat, i, result[stat], self.expected_stats[i][stat]))
                assert_equal(result[stat], self.expected_stats[i][stat])

        # Make sure only the selected statistics are included (more than one)
        some_stats = {'minfee', 'maxfee'}
        stats = self.nodes[0].getblockstats(
            hash_or_height=1, stats=list(some_stats))
        assert_equal(set(stats.keys()), some_stats)

        # Test invalid parameters raise the proper json exceptions
        tip = self.start_height + self.max_stat_pos
        assert_raises_rpc_error(-8, 'Target block height {} after current tip {}'.format(
            tip + 1, tip), self.nodes[0].getblockstats, hash_or_height=tip + 1)
        assert_raises_rpc_error(-8, 'Target block height {} is negative'.format(-1),
                                self.nodes[0].getblockstats, hash_or_height=-1)

        # Make sure not valid stats aren't allowed
        inv_sel_stat = 'asdfghjkl'
        inv_stats = [
            [inv_sel_stat],
            ['minfee', inv_sel_stat],
            [inv_sel_stat, 'minfee'],
            ['minfee', inv_sel_stat, 'maxfee'],
        ]
        for inv_stat in inv_stats:
            assert_raises_rpc_error(-8, 'Invalid selected statistic {}'.format(
                inv_sel_stat), self.nodes[0].getblockstats, hash_or_height=1, stats=inv_stat)

        # Make sure we aren't always returning inv_sel_stat as the culprit stat
        assert_raises_rpc_error(-8, 'Invalid selected statistic aaa{}'.format(inv_sel_stat),
                                self.nodes[0].getblockstats, hash_or_height=1, stats=['minfee', 'aaa{}'.format(inv_sel_stat)])

        assert_raises_rpc_error(-8, 'One or more of the selected stats requires -txindex enabled',
                                self.nodes[1].getblockstats, hash_or_height=self.start_height + self.max_stat_pos)

        # Mainchain's genesis block shouldn't be found on regtest
        assert_raises_rpc_error(-5, 'Block not found', self.nodes[0].getblockstats,
                                hash_or_height='000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f')


if __name__ == '__main__':
    GetblockstatsTest().main()
