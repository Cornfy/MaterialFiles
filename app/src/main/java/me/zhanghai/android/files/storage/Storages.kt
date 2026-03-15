/*
 * Copyright (c) 2019 Hai Zhang <dreaming.in.code.zh@gmail.com>
 * All Rights Reserved.
 */

package me.zhanghai.android.files.storage

import me.zhanghai.android.files.settings.Settings
import me.zhanghai.android.files.util.removeFirst
import me.zhanghai.android.files.util.valueCompat

import me.zhanghai.android.files.provider.sftp.client.PublicKeyAuthentication

object Storages {
    fun addOrReplace(storage: Storage) {
        // 修改：在保存前进行加密处理
        val storageToSave = encryptSftpServerIfNeeded(storage)
        
        val storages = Settings.STORAGES.valueCompat.toMutableList().apply {
            val index = indexOfFirst { it.id == storageToSave.id }
            if (index != -1) {
                this[index] = storageToSave
            } else {
                this += storageToSave
            }
        }
        Settings.STORAGES.putValue(storages)
    }

    // 新增辅助方法
    private fun encryptSftpServerIfNeeded(storage: Storage): Storage {
        if (storage is SftpServer && storage.authentication is PublicKeyAuthentication) {
            val auth = storage.authentication
            // 如果私钥还是明文（没有 KENC: 前缀），则加密
            val encryptedKey = SftpCryptoManager.encrypt(auth.privateKey)
            if (encryptedKey != auth.privateKey) {
                return SftpServer(
                    storage.id,
                    storage.customName,
                    storage.authority,
                    auth.copy(privateKey = encryptedKey!!),
                    storage.relativePath
                )
            }
        }
        return storage
    }

    // replace 方法也调用 encryptSftpServerIfNeeded
    fun replace(storage: Storage) {
        val storageToSave = encryptSftpServerIfNeeded(storage)
        val storages = Settings.STORAGES.valueCompat.toMutableList()
            .apply { this[indexOfFirst { it.id == storageToSave.id }] = storageToSave }
        Settings.STORAGES.putValue(storages)
    }

    fun move(fromPosition: Int, toPosition: Int) {
        val bookmarkDirectories = Settings.STORAGES.valueCompat.toMutableList()
            .apply { add(toPosition, removeAt(fromPosition)) }
        Settings.STORAGES.putValue(bookmarkDirectories)
    }

    fun remove(storage: Storage) {
        val bookmarkDirectories = Settings.STORAGES.valueCompat.toMutableList()
            .apply { removeFirst { it.id == storage.id } }
        Settings.STORAGES.putValue(bookmarkDirectories)
    }
}
