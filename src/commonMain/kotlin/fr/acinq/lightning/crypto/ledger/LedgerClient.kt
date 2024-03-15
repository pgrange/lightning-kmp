package fr.acinq.lightning.crypto.ledger

import fr.acinq.bitcoin.DeterministicWallet
import fr.acinq.bitcoin.KeyPath

class LedgerClient {
    fun getExtendedPublicKey(path: KeyPath): DeterministicWallet.ExtendedPublicKey {
        //TODO fail if the chain, as return as first from decode, is not the expected one?
        return DeterministicWallet.ExtendedPublicKey.decode(requestExtendedPublicKey(path)).second
    }

    private fun requestExtendedPublicKey(path: KeyPath): String {
        TODO()
    }
}
