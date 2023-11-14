package io.outblock.wallet

import android.util.Log
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature


object SignatureManager {

    private const val TAG = "SignatureManager"

    fun sign(
        privateKey: PrivateKey, text: String,
        domainTag: ByteArray = normalize(
            "FLOW-V0.0-user"
        ),
    ): ByteArray {
        return signData(privateKey, domainTag + text.encodeToByteArray())
    }

    fun signData(privateKey: PrivateKey, data: ByteArray): ByteArray {
        try {
            val signature = Signature.getInstance("SHA256withECDSA")
            val hashedData = sha256(data).hexStringToByteArray()
            signature.initSign(privateKey)
            signature.update(hashedData)
            val asn1Signature = signature.sign()
            val seq = ASN1Sequence.getInstance(asn1Signature)
            val r = (seq.getObjectAt(0) as ASN1Integer).value.toByteArray()
            val s = (seq.getObjectAt(1) as ASN1Integer).value.toByteArray()
            return (r.takeLast(32) + s.takeLast(32)).toByteArray()
        } catch (e: Exception) {
            Log.e(TAG, "Error while signing data: $e")
            throw KeyManagerException("Error signing data", e)
        }
    }

    @JvmStatic
    private fun normalize(tag: String): ByteArray {
        val bytes = tag.toByteArray(Charsets.UTF_8)
        return when {
            bytes.size > 32 -> throw IllegalArgumentException("Domain tags cannot be longer than 32 characters")
            bytes.size < 32 -> bytes + ByteArray(32 - bytes.size)
            else -> bytes
        }
    }

    private fun sha256(bytes: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(bytes)

        val result = StringBuilder()
        for (byte in digest) {
            result.append(String.format("%02x", byte))
        }

        return result.toString()
    }

    private fun String.hexStringToByteArray(): ByteArray {
        return chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }
}