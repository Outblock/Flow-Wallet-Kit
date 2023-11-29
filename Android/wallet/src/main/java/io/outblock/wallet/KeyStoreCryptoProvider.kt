package io.outblock.wallet

import com.nftco.flow.sdk.HashAlgorithm
import com.nftco.flow.sdk.SignatureAlgorithm
import com.nftco.flow.sdk.Signer
import com.nftco.flow.sdk.bytesToHex


class KeyStoreCryptoProvider(private val prefix: String): CryptoProvider {

    override fun getPublicKey(): String {
        return KeyManager.getPublicKeyByPrefix(prefix).toFormatString()
    }

    override fun getUserSignature(jwt: String): String {
        return getSigner().signAsUser(
            jwt.encodeToByteArray()
        ).bytesToHex()
    }

    override fun signData(data: ByteArray): String {
        return getSigner().sign(data).bytesToHex()
    }

    override fun getSigner(): Signer {
        val privateKey = KeyManager.getPrivateKeyByPrefix(prefix)
        return WalletCoreSigner(privateKey)
    }

    override fun getHashAlgorithm(): HashAlgorithm {
        return HashAlgorithm.SHA2_256
    }

    override fun getSignatureAlgorithm(): SignatureAlgorithm {
        return SignatureAlgorithm.ECDSA_P256
    }
}