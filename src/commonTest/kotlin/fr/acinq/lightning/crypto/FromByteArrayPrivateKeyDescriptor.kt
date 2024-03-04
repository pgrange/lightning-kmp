package fr.acinq.lightning.crypto

import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey

class FromByteArrayPrivateKeyDescriptor(private val byteArray: ByteArray) :
    PrivateKeyDescriptor {
    override fun instantiate(): PrivateKey {
        return PrivateKey(byteArray)
    }

    override fun publicKey(): PublicKey {
        return instantiate().publicKey()
    }

}
