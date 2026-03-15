/*
 * Copyright (c) 2021 Hai Zhang <dreaming.in.code.zh@gmail.com>
 * All Rights Reserved.
 */

package me.zhanghai.android.files.provider.sftp.client

import android.os.Parcelable
import kotlinx.parcelize.Parcelize
import net.schmizz.sshj.DefaultConfig
import net.schmizz.sshj.common.Factory
import net.schmizz.sshj.userauth.keyprovider.KeyProvider
import net.schmizz.sshj.userauth.keyprovider.KeyProviderUtil
import net.schmizz.sshj.userauth.method.AuthMethod
import net.schmizz.sshj.userauth.method.AuthPassword
import net.schmizz.sshj.userauth.method.AuthPublickey
import net.schmizz.sshj.userauth.password.PasswordUtils
import java.io.IOException

import me.zhanghai.android.files.storage.SftpCryptoManager

sealed class Authentication : Parcelable {
    abstract fun toAuthMethod(): AuthMethod
}

@Parcelize
data class PasswordAuthentication(
    val password: String
) : Authentication() {
    override fun toAuthMethod(): AuthMethod =
        AuthPassword(PasswordUtils.createOneOff(password.toCharArray()))
}

@Parcelize
data class PublicKeyAuthentication(
    val privateKey: String,
    val privateKeyPassword: String?
) : Authentication() {
    override fun toAuthMethod(): AuthMethod {
        // 修改：在这里调用解密。
        // SftpCryptoManager.decrypt 会自动判断：如果是 KENC: 就解密，否则返回原样（兼容明文）
        val decryptedKey = SftpCryptoManager.decrypt(privateKey) ?: ""
        return AuthPublickey(createKeyProvider(decryptedKey, privateKeyPassword))
    }

    companion object {
        private val KEY_PROVIDER_FACTORIES = DefaultConfig().fileKeyProviderFactories

        fun validate(privateKey: String, privateKeyPassword: String?): IOException? =
            try {
                // 同样进行解密，确保校验的是明文
                val decryptedKey = SftpCryptoManager.decrypt(privateKey) ?: ""
                createKeyProvider(decryptedKey, privateKeyPassword).private
                null
            } catch (e: IOException) {
                e
            }

        /**
         * @see net.schmizz.sshj.SSHClient.loadKeys
         */
        @Throws(IOException::class)
        private fun createKeyProvider(
            privateKey: String,
            privateKeyPassword: String?
        ): KeyProvider {
            val format = KeyProviderUtil.detectKeyFileFormat(privateKey, false)
            val keyProvider = Factory.Named.Util.create(KEY_PROVIDER_FACTORIES, format.toString())
                ?: throw IOException("No key provider factory found for $format")
            keyProvider.init(
                privateKey, null,
                privateKeyPassword?.let { PasswordUtils.createOneOff(it.toCharArray()) }
            )
            return keyProvider
        }
    }
}
