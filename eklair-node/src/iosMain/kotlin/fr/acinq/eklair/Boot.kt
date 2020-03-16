package fr.acinq.eklair

import fr.acinq.eklair.crypto.Pack.uint16
import fr.acinq.eklair.crypto.Pack.write16
import fr.acinq.eklair.crypto.noise.*
import fr.acinq.secp256k1.Secp256k1
import kotlinx.coroutines.*

@ExperimentalStdlibApi
actual object Boot {
     actual fun main(args: Array<String>) {
        val priv = ByteArray(32) { 0x01.toByte() }
        val pub = Secp256k1.computePublicKey(priv)
        val keyPair = Pair(pub, priv)
        //val nodeId = Hex.decode("032ddfc80ee130a8f10823649fcc2fdeb88281acf89f568a41cbdde96530b9f9f7")
        val nodeId = Hex.decode("02413957815d05abb7fc6d885622d5cdc5b7714db1478cb05813a8474179b83c5c")

        val prefix: Byte = 0x00
        val prologue = "lightning".encodeToByteArray()


        fun makeWriter(localStatic: Pair<ByteArray, ByteArray>, remoteStatic: ByteArray) = HandshakeState.initializeWriter(
                handshakePatternXK, prologue,
                localStatic, Pair(ByteArray(0), ByteArray(0)), remoteStatic, ByteArray(0),
                Secp256k1DHFunctions, Chacha20Poly1305CipherFunctions, SHA256HashFunctions)

        fun makeReader(localStatic: Pair<ByteArray, ByteArray>) = HandshakeState.initializeReader(
                handshakePatternXK, prologue,
                localStatic, Pair(ByteArray(0), ByteArray(0)), ByteArray(0), ByteArray(0),
                Secp256k1DHFunctions, Chacha20Poly1305CipherFunctions, SHA256HashFunctions)

        class LightningSession(val socket: NativeSocket, val enc: CipherState, val dec: CipherState, val ck: ByteArray) {
            var encryptor: CipherState = ExtendedCipherState(enc, ck)
            var decryptor: CipherState = ExtendedCipherState(dec, ck)

            suspend fun receive(): ByteArray {
                val cipherlen = ByteArray(18)
                socket.suspendRecvExact(cipherlen, 0, 18)
                val (tmp, plainlen) = decryptor.decryptWithAd(ByteArray(0), cipherlen)
                decryptor = tmp
                val length = uint16(plainlen, 0)
                val cipherbytes = ByteArray(length + 16)
                socket.suspendRecvExact(cipherbytes, 0, cipherbytes.size)
                val (tmp1, plainbytes) = decryptor.decryptWithAd(ByteArray(0), cipherbytes)
                decryptor = tmp1
                return plainbytes
            }

            suspend fun send(data: ByteArray): Unit {
                val plainlen = write16(data.size)
                val (tmp, cipherlen) = encryptor.encryptWithAd(ByteArray(0), plainlen)
                encryptor = tmp
                socket.suspendSend(cipherlen, 0, cipherlen.size)
                val (tmp1, cipherbytes) = encryptor.encryptWithAd(ByteArray(0), data)
                encryptor = tmp1
                socket.suspendSend(cipherbytes, 0, cipherbytes.size)
            }
        }


        suspend fun handshake(ourKeys: Pair<ByteArray, ByteArray>, theirPubkey: ByteArray, nativeSocket: NativeSocket): Triple<CipherState, CipherState, ByteArray> {


            /**
             * See BOLT #8: during the handshake phase we are expecting 3 messages of 50, 50 and 66 bytes (including the prefix)
             *
             * @param reader handshake state reader
             * @return the size of the message the reader is expecting
             */

            fun expectedLength(reader: HandshakeStateReader): Int = when (reader.messages.size) {
                3, 2 -> 50
                1 -> 66
                else -> throw RuntimeException("invalid state")
            }
            nativeSocket.setSocketBlockingEnabled(false)

            val writer = makeWriter(ourKeys, theirPubkey)
            val (state1, message, _) = writer.write(ByteArray(0))
            val prefixByteArray = ByteArray(1) { prefix }
            println("Send prefix ${Hex.encode(prefixByteArray)}")
            nativeSocket.suspendSend(prefixByteArray)

            println("Send initial message ${Hex.encode(message)}")
            nativeSocket.suspendSend(message)
            println("Waiting initial response...")
            val byteArray = nativeSocket.suspendRecvUpTo(expectedLength(state1))
            assert(byteArray[0] == prefix)

            println("Received response ${Hex.encode(byteArray)}")

            val (writer1, a, b) = state1.read(byteArray.drop(1).toByteArray())
            val (reader1, message1, foo) = writer1.write(ByteArray(0))
            val (enc, dec, ck) = foo!!
            nativeSocket.suspendSend(prefixByteArray)
            nativeSocket.suspendSend(message1)
            return Triple(enc, dec, ck)
        }


        runBlocking {
            println("===> Acinq Connecting....")
            withTimeoutOrNull(60000) {
                val connect = NativeSocket.connect("51.77.223.203", 19735)
                println("connect = ${connect}")
                val (enc, dec, ck) = handshake(keyPair, nodeId, connect)
                println("enc = ${enc}")
                println("dec = ${dec}")
                println("ck = ${Hex.encode(ck)}")
                val session = LightningSession(connect, enc, dec, ck)
                println("session = ${session}")
                val ping = Hex.decode("0012000a0004deadbeef")
                println("encoded ping = ${Hex.encode(ping)}")
                while (true) {
                    session.send(ping)
                    val received = session.receive()
                    println("Received ping ${Hex.encode(received)}")
                }
            }
        }
    }
}
