package fr.acinq.lightning.crypto

import fr.acinq.bitcoin.DeterministicWallet
import fr.acinq.bitcoin.PrivateKey

interface ExtendedPrivateKeyDescriptor {
    fun instantiate(): DeterministicWallet.ExtendedPrivateKey

    fun publicKey(): DeterministicWallet.ExtendedPublicKey

    fun derivePrivateKey(index: Long): PrivateKeyDescriptor
}