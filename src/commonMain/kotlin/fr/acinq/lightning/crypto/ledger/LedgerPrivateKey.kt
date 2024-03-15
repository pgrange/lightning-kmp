package fr.acinq.lightning.crypto.ledger

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.ByteVector64
import fr.acinq.bitcoin.Crypto
import fr.acinq.bitcoin.KeyPath
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.Satoshi
import fr.acinq.bitcoin.ScriptTree
import fr.acinq.bitcoin.SigHash
import fr.acinq.bitcoin.SigVersion
import fr.acinq.bitcoin.Transaction
import fr.acinq.bitcoin.TxOut
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce
import fr.acinq.bitcoin.crypto.musig2.Musig2
import fr.acinq.bitcoin.crypto.musig2.SecretNonce
import fr.acinq.bitcoin.utils.Either
import fr.acinq.lightning.crypto.PrivateKeyDescriptor
import fr.acinq.lightning.transactions.Transactions

class LedgerPrivateKey(private val client: LedgerClient, private val path: KeyPath) : PrivateKeyDescriptor {

    override fun publicKey(): PublicKey {
        return client.getExtendedPublicKey(path).publicKey
    }

    override fun deriveForRevocation(perCommitSecret: PrivateKey): PrivateKeyDescriptor {
        TODO("Not yet implemented")
    }

    override fun deriveForCommitment(perCommitPoint: PublicKey): PrivateKeyDescriptor {
        TODO("Not yet implemented")
    }

    override fun sign(data: ByteVector32): ByteVector {
        TODO("Not yet implemented")
    }

    override fun sign(
        tx: Transaction,
        inputIndex: Int,
        redeemScript: ByteArray,
        amount: Satoshi,
        sighash: Int
    ): ByteVector64 {
        TODO("Not yet implemented")
    }

    override fun sign(txInfo: Transactions.TransactionWithInputInfo, sighash: Int): ByteVector64 {
        TODO("Not yet implemented")
    }

    override fun signInputTaprootScriptPath(
        tx: Transaction,
        inputIndex: Int,
        inputs: List<TxOut>,
        sigHash: Int,
        tapleaf: ByteVector32
    ): ByteVector64 {
        TODO("Not yet implemented")
    }

    override fun signMusig2TaprootInput(
        tx: Transaction,
        index: Int,
        inputs: List<TxOut>,
        publicKeys: List<PublicKey>,
        secretNonce: SecretNonce,
        publicNonces: List<IndividualNonce>,
        scriptTree: ScriptTree.Leaf
    ): Either<Throwable, ByteVector32> {
        TODO("Not yet implemented")
    }

    override fun generateMusig2Nonce(
        sessionId: ByteVector32,
        publicKeys: List<PublicKey>
    ): Pair<SecretNonce, IndividualNonce> {
        TODO("Not yet implemented")
    }
}
