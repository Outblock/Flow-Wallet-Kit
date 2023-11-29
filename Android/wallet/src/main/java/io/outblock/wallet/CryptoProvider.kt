package io.outblock.wallet

import com.nftco.flow.sdk.HashAlgorithm
import com.nftco.flow.sdk.SignatureAlgorithm
import com.nftco.flow.sdk.Signer


interface CryptoProvider {
    fun getPublicKey(): String
    fun getUserSignature(jwt: String): String
    fun signData(data: ByteArray): String
    fun getSigner(): Signer
    fun getHashAlgorithm(): HashAlgorithm
    fun getSignatureAlgorithm(): SignatureAlgorithm
}