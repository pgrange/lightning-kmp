package fr.acinq.lightning.crypto

import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey

class FromBytes32PrivateKeyDescriptor(private val byteArray: ByteVector32) :
    PrivateKeyDescriptor {
    override fun instantiate(): PrivateKey {
        return PrivateKey(byteArray)
    }

    override fun publicKey(): PublicKey {
        return instantiate().publicKey()
    }

}
