#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test Secret Mining code
#

import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.address import script_to_p2sh
from test_framework.mininode import (
    mininode_lock,
    P2PInterface,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    ToHex,
    msg_mempool,
)
from test_framework.script import (
    CScript,
    OP_RETURN,
)
from test_framework.util import assert_raises_rpc_error, sync_blocks, wait_until

# Use a segwit recovery for the nonstandard spend.
nonstd_p2sh_redeemscript = bytes.fromhex('00021111')
nonstd_p2sh_spendscript = CScript([nonstd_p2sh_redeemscript])
nonstd_p2sh_addr = script_to_p2sh(nonstd_p2sh_redeemscript)
nonstd_error = "non-mandatory-script-verify-flag (Extra items left on stack after execution) (code 64)"


class MyMiniNode(P2PInterface):
    def __init__(self):
        super().__init__()
        self.txinvs = set()

    def on_inv(self, message):
        with mininode_lock:
            for i in message.inv:
                if (i.type == 1):
                    self.txinvs.add('{:064x}'.format(i.hash))

    def clear_invs(self):
        with mininode_lock:
            self.txinvs = set()

    def match_inv_txids(self, txids_expected):
        set_expected = set(txids_expected)

        def fun():
            return set_expected == self.txinvs
        wait_until(fun)


class SecretMinerTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        # we put whitelist so that node0 sends out transactions quickly, and doesn't trickle them.
        self.extra_args = [["-acceptnonstdtxn=0",
                            "-whitelist=127.0.0.1"], ["-acceptnonstdtxn=0"], ]

    def run_test(self):
        self.log.debug("Connect mininode")
        self.nodes[0].add_p2p_connection(MyMiniNode())
        self.nodes[0].p2p.wait_for_verack()

        self.log.debug("Get out of IBD")
        self.nodes[0].generate(1)
        sync_blocks(self.nodes)

        # Funding
        self.log.info(
            "Making a secret (but standard) funding to {}".format(nonstd_p2sh_addr))
        txraw = self.nodes[0].createrawtransaction(
            [], [{nonstd_p2sh_addr: 0.00002}])
        txraw = self.nodes[0].fundrawtransaction(
            txraw, {'changePosition': 1})['hex']
        txraw = self.nodes[0].signrawtransactionwithwallet(txraw)['hex']

        self.log.debug("Made tx: {}".format(txraw))

        self.log.info("Secret-mempooling the txn")
        txid_secret_fund = self.nodes[0].sendrawtransaction(txraw, False, True)
        assert txid_secret_fund in self.nodes[0].getrawmempool()
        time.sleep(0.5)
        assert txid_secret_fund not in self.nodes[1].getrawmempool()
        assert not self.nodes[0].p2p.txinvs

        self.log.info(
            "Making & broadcasting a normal tx, just to have something else in mempool")
        txid_normal = self.nodes[0].sendtoaddress(
            self.nodes[1].getnewaddress(), 1)
        assert txid_normal in self.nodes[0].getrawmempool()
        time.sleep(0.5)
        assert txid_normal in self.nodes[1].getrawmempool()
        self.nodes[0].p2p.match_inv_txids([txid_normal])

        self.log.info("Sending a mempool request")
        # Make sure the mininode is synced
        self.nodes[0].p2p.clear_invs()
        self.nodes[0].p2p.send_message(msg_mempool())
        # Inv response has the normal transaction, but not the secret transaction.
        self.nodes[0].p2p.match_inv_txids([txid_normal])
        self.nodes[0].p2p.clear_invs()

        self.log.info(
            "Mining the secret txn (txid={})".format(txid_secret_fund))
        genblockhash, = self.nodes[0].generate(1)
        # Make sure the secret tx made it into the block
        assert txid_secret_fund in self.nodes[0].getblock(genblockhash)["tx"]
        sync_blocks(self.nodes)

        # Spending
        self.log.info("Making a nonstandard spend")
        txspend = CTransaction()
        txspend.vin.append(
            CTxIn(COutPoint(int(txid_secret_fund, 16), 0), nonstd_p2sh_spendscript))
        txspend.vout.append(CTxOut(0, CScript([OP_RETURN, b'pad'*20])))
        txspend.rehash()
        txraw = ToHex(txspend)

        self.log.debug("Made tx: {}".format(txraw))

        self.log.info("Secret-mempooling the nonstandard txn")
        assert_raises_rpc_error(-26, nonstd_error,
                                self.nodes[0].sendrawtransaction, txraw)
        txid_nonstandard = self.nodes[0].sendrawtransaction(txraw, False, True)
        assert txid_nonstandard in self.nodes[0].getrawmempool()
        time.sleep(0.5)
        assert txid_nonstandard not in self.nodes[1].getrawmempool()
        assert not self.nodes[0].p2p.txinvs

        self.log.info(
            "Mining the secret txn (txid={})".format(txid_nonstandard))
        genblockhash, = self.nodes[0].generate(1)
        # Make sure the secret tx made it into the block
        assert txid_nonstandard in self.nodes[0].getblock(genblockhash)["tx"]
        sync_blocks(self.nodes)


if __name__ == '__main__':
    SecretMinerTest().main()
