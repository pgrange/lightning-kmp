package fr.acinq.lightning.crypto.ledger

import fr.acinq.bitcoin.DeterministicWallet
import fr.acinq.bitcoin.KeyPath
import fr.acinq.lightning.crypto.ExtendedPrivateKeyDescriptor
import fr.acinq.lightning.crypto.PrivateKeyDescriptor

class LedgerMasterKey(private val client: LedgerClient, private val path: KeyPath) : ExtendedPrivateKeyDescriptor {
    override fun privateKey(): PrivateKeyDescriptor {
        TODO("Not yet implemented")
    }

    override fun publicKey(): DeterministicWallet.ExtendedPublicKey {
        return client.getExtendedPublicKey(path)
    }

    override fun derive(path: KeyPath): ExtendedPrivateKeyDescriptor {
        TODO("Not yet implemented")
    }

    override fun derivePrivateKey(index: Long): PrivateKeyDescriptor {
        TODO("Not yet implemented")
    }

    override fun derivePrivateKey(path: KeyPath): PrivateKeyDescriptor {
        TODO("Not yet implemented")
    }

}