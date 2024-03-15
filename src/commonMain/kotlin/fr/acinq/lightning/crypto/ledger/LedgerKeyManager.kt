package fr.acinq.lightning.crypto.ledger

import fr.acinq.bitcoin.ByteVector
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.Chain
import fr.acinq.bitcoin.Crypto
import fr.acinq.bitcoin.DeterministicWallet
import fr.acinq.bitcoin.KeyPath
import fr.acinq.bitcoin.PublicKey
import fr.acinq.lightning.Lightning
import fr.acinq.lightning.crypto.KeyManager
import fr.acinq.lightning.crypto.LocalKeyManager
import fr.acinq.lightning.crypto.LocalKeyManager.Companion.channelKeyPath
import fr.acinq.lightning.crypto.PrivateKeyDescriptor
import fr.acinq.lightning.crypto.div
import fr.acinq.lightning.crypto.local.LocalExtendedPrivateKeyDescriptor
import fr.acinq.lightning.crypto.local.LocalPrivateKeyDescriptor
import fr.acinq.lightning.crypto.local.RootExtendedPrivateKeyDescriptor

/**
 * An implementation of [KeyManager] that supports deterministic derivation for [KeyManager.ChannelKeys] based
 * on the initial funding pubkey.
 *
 * Specifically, for channel keys there are two paths:
 *   - `fundingKeyPath`: chosen at random using [newFundingKeyPath]
 *   - `channelKeyPath`: computed from `fundingKeyPath` using [channelKeyPath]
 *
 * The resulting paths looks like so on mainnet:
 * ```
 *  node key:
 *       50' / 0'
 *
 *  funding keys:
 *       50' / 1' / <fundingKeyPath> / <0' or 1'> / <index>'
 *
 *  others channel basepoint keys (payment, revocation, htlc, etc.):
 *       50' / 1' / <channelKeyPath> / <1'-5'>
 *
 *  bip-84 on-chain keys:
 *       84' / 0' / <account>' / <0' or 1'> / <index>
 * ```
 *
 * @param seed seed from which the channel keys will be derived
 * @param remoteSwapInExtendedPublicKey xpub belonging to our swap-in server, that must be used in our swap address
 */
data class LedgerKeyManager(val seed: ByteVector, val chain: Chain, val remoteSwapInExtendedPublicKey: String) :
    KeyManager {

    val local_master = DeterministicWallet.generate(seed)
    //TODO: use another master, one that relies on LedgerKeyDescriptor
    private val master = RootExtendedPrivateKeyDescriptor(local_master)

    private val channelKeyBasePath: KeyPath = LocalKeyManager.channelKeyBasePath(chain)

    override val nodeKeys: KeyManager.NodeKeys = KeyManager.NodeKeys(
        legacyNodeKey = @Suppress("DEPRECATION")   (master.derive(LocalKeyManager.eclairNodeKeyBasePath(chain)) as LocalExtendedPrivateKeyDescriptor).instantiate(),
        nodeKey = DeterministicWallet.generate(deterministicKeyMaterial(LocalKeyManager.nodeKeyBasePath(chain)))
        )

    override fun newFundingKeyPath(isInitiator: Boolean): KeyPath {
        val last = DeterministicWallet.hardened(if (isInitiator) 1 else 0)
        fun next() = Lightning.secureRandom.nextInt().toLong() and 0xFFFFFFFF
        return KeyPath.empty / next() / next() / next() / next() / next() / next() / next() / next() / last
    }

    override fun channelKeys(fundingKeyPath: KeyPath): KeyManager.ChannelKeys {
        // We use a different funding key for each splice, with a derivation based on the fundingTxIndex.
        val fundingKey: (Long) -> PrivateKeyDescriptor = { index -> master.derivePrivateKey(channelKeyBasePath / fundingKeyPath / DeterministicWallet.hardened(
            index
        )
        ) }
        // We use the initial funding pubkey to compute the channel key path, and we use the recovery process even
        // in the normal case, which guarantees it works all the time.
        val initialFundingPubkey = fundingKey(0).publicKey()
        val recoveredChannelKeys = recoverChannelKeys(initialFundingPubkey)
        return KeyManager.ChannelKeys(
            fundingKeyPath,
            fundingKey = fundingKey,
            paymentKey = recoveredChannelKeys.paymentKey,
            delayedPaymentKey = recoveredChannelKeys.delayedPaymentKey,
            htlcKey = recoveredChannelKeys.htlcKey,
            revocationKey = recoveredChannelKeys.revocationKey,
            shaSeed = recoveredChannelKeys.shaSeed
        )
    }

    /**
     * Generate channel-specific keys and secrets (note that we cannot re-compute the channel's funding private key)
     * @params fundingPubKey funding public key
     * @return channel keys and secrets
     */
    private fun recoverChannelKeys(fundingPubKey: PublicKey): LocalKeyManager.RecoveredChannelKeys {
        val channelKeyPrefix = channelKeyBasePath / channelKeyPath(fundingPubKey)
        return LocalKeyManager.RecoveredChannelKeys(
            fundingPubKey,
            paymentKey = master.derivePrivateKey(channelKeyPrefix / DeterministicWallet.hardened(2)),
            delayedPaymentKey = master.derivePrivateKey(
                channelKeyPrefix / DeterministicWallet.hardened(
                    3
                )
            ),
            htlcKey = master.derivePrivateKey(channelKeyPrefix / DeterministicWallet.hardened(4)),
            revocationKey = master.derivePrivateKey(
                channelKeyPrefix / DeterministicWallet.hardened(
                    1
                )
            ),
            shaSeed = (master.derivePrivateKey(channelKeyPrefix / DeterministicWallet.hardened(5)) as LocalPrivateKeyDescriptor)
                .instantiate().value.concat(1).sha256()
        )
    }

    /**
     * This method offers direct access to the master key derivation. It should only be used for some advanced usage
     * like (LNURL-auth, data encryption).
     */
    override fun derivePrivateKey(keyPath: KeyPath): PrivateKeyDescriptor = master.derivePrivateKey(keyPath)

    override fun deterministicKeyMaterial(keyPath: KeyPath): ByteVector32 {
        // TODO: use ledger to deterministically generate this data
        //       if we use the standard bitcoin application, maybe we
        //       want to rely on signMessage...
        //       Of course it would just be for a poc as an attacker might
        //       trick the user into signing a message that just happens to
        //       be this one and boum! They get the node key for instance.
        return ByteVector32(Crypto.sign(keyPath.toString().encodeToByteArray(), local_master.privateKey))
    }

    override val finalOnChainWallet: KeyManager.Bip84OnChainKeys = KeyManager.Bip84OnChainKeys(chain, master,  account = 0)

    override val swapInOnChainWallet: KeyManager.SwapInOnChainKeys = run {
        val (prefix, xpub) = DeterministicWallet.ExtendedPublicKey.decode(remoteSwapInExtendedPublicKey)
        val expectedPrefix = when (chain) {
            Chain.Mainnet -> DeterministicWallet.xpub
            else -> DeterministicWallet.tpub
        }
        require(prefix == expectedPrefix) { "unexpected swap-in xpub prefix $prefix (expected $expectedPrefix)" }
        val remoteSwapInPublicKey = DeterministicWallet.derivePublicKey(xpub, KeyManager.SwapInOnChainKeys.perUserPath(nodeKeys.nodeKey.publicKey)).publicKey
        KeyManager.SwapInOnChainKeys(chain, master,  remoteSwapInPublicKey)
    }
}