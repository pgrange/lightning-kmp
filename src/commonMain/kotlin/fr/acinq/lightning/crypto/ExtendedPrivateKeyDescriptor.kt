package fr.acinq.lightning.crypto

import fr.acinq.bitcoin.DeterministicWallet
import fr.acinq.bitcoin.PrivateKey

interface ExtendedPrivateKeyDescriptor {
    abstract fun instantiate(): DeterministicWallet.ExtendedPrivateKey

    abstract fun publicKey(): DeterministicWallet.ExtendedPublicKey

    abstract fun derivePrivateKey(index: Long): PrivateKeyDescriptor
}