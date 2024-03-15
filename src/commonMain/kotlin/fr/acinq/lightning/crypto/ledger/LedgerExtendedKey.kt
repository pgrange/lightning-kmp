package fr.acinq.lightning.crypto.ledger

import fr.acinq.bitcoin.DeterministicWallet
import fr.acinq.bitcoin.KeyPath
import fr.acinq.lightning.crypto.ExtendedPrivateKeyDescriptor
import fr.acinq.lightning.crypto.PrivateKeyDescriptor
import fr.acinq.lightning.crypto.div

class LedgerExtendedKey(private val client: LedgerClient, private val path: KeyPath) : ExtendedPrivateKeyDescriptor {
    override fun privateKey(): PrivateKeyDescriptor {
        return LedgerPrivateKey(client, path)
    }

    override fun publicKey(): DeterministicWallet.ExtendedPublicKey {
        return client.getExtendedPublicKey(path)
    }

    override fun derive(path: KeyPath): ExtendedPrivateKeyDescriptor {
        return LedgerExtendedKey(client, this.path / path)
    }

    override fun derivePrivateKey(index: Long): PrivateKeyDescriptor {
        return LedgerPrivateKey(client, this.path / index)
    }

    override fun derivePrivateKey(path: KeyPath): PrivateKeyDescriptor {
        return LedgerPrivateKey(client, this.path / path)
    }
}