package com.cncverse

import android.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object SKLiveCryptoUtils {
    
    // V25 Keys from BuildConfig
    private val V25_KEY1 = BuildConfig.SKLIVE_V25_KEY1.toByteArray(Charsets.UTF_8)
    private val V25_KEY2 = BuildConfig.SKLIVE_V25_KEY2.toByteArray(Charsets.UTF_8)
    private val V25_IV   = BuildConfig.SKLIVE_V25_IV.toByteArray(Charsets.UTF_8)

    // V23 Keys from BuildConfig
    private val V23_KEY = BuildConfig.SKLIVE_V23_KEY.toByteArray(Charsets.UTF_8)
    private val V23_IV  = BuildConfig.SKLIVE_V23_IV.toByteArray(Charsets.UTF_8)

    // Legacy Keys from BuildConfig
    private val LEGACY_AES_KEY = hexStringToByteArray(BuildConfig.SKLIVE_KEY)
    private val LEGACY_AES_IV  = hexStringToByteArray(BuildConfig.SKLIVE_IV)

    private const val LOOKUP_TABLE_D = "\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007\b\t\n\u000B\u000C\r\u000E\u000F" +
        "\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017\u0018\u0019\u001A\u001B\u001C\u001D\u001E\u001F" +
        " !\"#\$%&'()*+,-./0123456789:;<=>?@EGMNKABUVCDYHLIFPOZQSRWTXJ[\\]^_`egmnkabuvcdyhlifpozqsrwtxj{|}~\u007F"

    private fun hexStringToByteArray(hex: String): ByteArray {
        val len = hex.length
        val data = ByteArray(len / 2)
        for (i in 0 until len step 2) {
            data[i / 2] = ((Character.digit(hex[i], 16) shl 4) + Character.digit(hex[i + 1], 16)).toByte()
        }
        return data
    }

    private fun padBase64(s: String): String {
        return if (s.length % 4 != 0) s + "=".repeat(4 - (s.length % 4)) else s
    }

    private fun aesDecryptAndTransform(ciphertext: ByteArray, key: ByteArray, iv: ByteArray): ByteArray? {
        return try {
            if (ciphertext.size % 16 != 0) return null
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            val plain = cipher.doFinal(ciphertext).toMutableList()
            
            for (i in 0 until plain.size - 1 step 2) {
                val tmp = plain[i]
                plain[i] = plain[i + 1]
                plain[i + 1] = tmp
            }
            plain.reverse()
            plain.toByteArray()
        } catch (e: Exception) {
            null
        }
    }

    private fun prepareCiphertext(encryptedData: String): ByteArray? {
        val src = if (encryptedData.startsWith("==")) encryptedData.reversed() else encryptedData
        return try {
            val decoded = Base64.decode(padBase64(src), Base64.DEFAULT)
            if (decoded.size > 12 && decoded.size % 16 == 12) {
                decoded.copyOfRange(12, decoded.size)
            } else if (decoded.size % 16 == 0) {
                decoded
            } else null
        } catch (e: Exception) {
            null
        }
    }

    private fun decryptV25Pass1(encryptedData: String): String? {
        val ciphertext = prepareCiphertext(encryptedData) ?: return null
        val plain = aesDecryptAndTransform(ciphertext, V23_KEY, V25_KEY1) ?: return null
        return try {
            val decodedFinal = Base64.decode(plain, Base64.DEFAULT)
            val s = String(decodedFinal, Charsets.UTF_8)
            val firstChar = s.trimStart().firstOrNull()
            if (firstChar == '[' || firstChar == '{') s else null
        } catch (e: Exception) {
            null
        }
    }

    private fun decryptV25Pass2(encryptedData: String): String? {
        val ciphertext = prepareCiphertext(encryptedData) ?: return null
        val plain = aesDecryptAndTransform(ciphertext, V23_KEY, V25_KEY2) ?: return null
        return try {
            val decodedFinal = Base64.decode(plain, Base64.DEFAULT)
            val s = String(decodedFinal, Charsets.UTF_8)
            val firstChar = s.trimStart().firstOrNull()
            if (firstChar == '[' || firstChar == '{') s else null
        } catch (e: Exception) {
            null
        }
    }

    private fun decryptV23(encryptedData: String): String? {
        return try {
            val inner = Base64.decode(padBase64(encryptedData), Base64.DEFAULT).toMutableList()
            for (i in 0 until inner.size - 1 step 2) {
                val tmp = inner[i]
                inner[i] = inner[i + 1]
                inner[i + 1] = tmp
            }
            inner.reverse()
            val ciphertext = Base64.decode(inner.toByteArray(), Base64.DEFAULT)
            if (ciphertext.size % 16 != 0) return null
            
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(V23_KEY, "AES"), IvParameterSpec(V23_IV))
            val plaintext = cipher.doFinal(ciphertext)
            val s = String(plaintext, Charsets.UTF_8)
            val firstChar = s.trimStart().firstOrNull()
            if (firstChar == '[' || firstChar == '{') s else null
        } catch (e: Exception) {
            null
        }
    }

    private fun decryptLegacy(encryptedData: String): String? {
        return try {
            val standardB64 = customToStandardBase64(encryptedData)
            val ciphertext = Base64.decode(standardB64, Base64.DEFAULT)
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(LEGACY_AES_KEY, "AES"), IvParameterSpec(LEGACY_AES_IV))
            val decrypted = cipher.doFinal(ciphertext)
            String(decrypted, Charsets.UTF_8)
        } catch (e: Exception) {
            null
        }
    }

    private fun customToStandardBase64(customB64: String): String {
        val result = java.lang.StringBuilder()
        for (i in 0 until customB64.length) {
            val cCharAt = customB64[i]
            if (cCharAt.code < LOOKUP_TABLE_D.length) {
                result.append(LOOKUP_TABLE_D[cCharAt.code])
            } else {
                result.append(cCharAt)
            }
        }
        return result.toString()
    }

    private fun preprocessResponse(rawResponse: String): String? {
        return try {
            val charArray = rawResponse.toCharArray()
            for (i in 0 until charArray.size - 1 step 2) {
                val temp = charArray[i]
                charArray[i] = charArray[i + 1]
                charArray[i + 1] = temp
            }
            val reversed = String(charArray).reversed()
            val decodedBytes = Base64.decode(reversed, Base64.DEFAULT)
            val str2 = String(decodedBytes, Charsets.UTF_8)
            if (!str2.endsWith("BA@GBA@GBA@GBA@G")) return null
            str2.substring(0, str2.length - "BA@GBA@GBA@GBA@G".length)
        } catch (e: Exception) {
            null
        }
    }

    fun decryptSKLive(encryptedData: String): String? {
        val preprocessed = preprocessResponse(encryptedData)
        val v25Input = preprocessed ?: encryptedData
        
        decryptV25Pass1(v25Input)?.let { return it }
        decryptV25Pass2(v25Input)?.let { return it }
        decryptV23(encryptedData)?.let { return it }
        decryptLegacy(v25Input)?.let { return it }
        
        val legacyInput = try {
            String(Base64.decode(encryptedData, Base64.DEFAULT), Charsets.UTF_8)
        } catch (e: Exception) {
            encryptedData
        }
        
        decryptLegacy(legacyInput)?.let { return it }
        if (legacyInput != encryptedData) {
            decryptLegacy(encryptedData)?.let { return it }
        }
        return null
    }
}