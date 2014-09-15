package com.helloclue.gradle.crypto

import org.gradle.api.Project
import org.gradle.api.Plugin
import org.gradle.api.DefaultTask
import org.gradle.api.tasks.TaskAction

import java.security.Security
import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.Cipher

import org.bouncycastle.jce.provider.BouncyCastleProvider

/**
 * @author pelle
 * Created: Wed Sep 03 15:26:28 CEST 2014
 */
class CryptoPlugin implements Plugin<Project> {

  void apply (Project project) {
    project.extensions.create('gradleCrypto', CryptoPluginExtension)
    project.task('encrypt', type: CryptoPluginEncryptTask)
    project.task('decrypt', type: CryptoPluginDecryptTask)
  }
}

class CryptoPluginExtension {
  byte[] ciphertext = null
  byte[] key = null
  byte[] iv = null
  byte[] plaintext = null
  int plaintextLength = 0
  int ciphertextLength = 0
}

class CryptoPluginBaseTask extends DefaultTask {
  Cipher cipher

  CryptoPluginBaseTask() {
    Security.addProvider(new BouncyCastleProvider())
    cipher = Cipher.getInstance('AES/CBC/PKCS7Padding', 'BC')
  }

  SecretKeySpec createKeyFromBytes(byte[] bytes) {
    new SecretKeySpec(bytes, 'AES')
  }

  byte[] encrypt (byte[] plaintext, SecretKeySpec key) {
    cipher.init(Cipher.ENCRYPT_MODE, key)
    byte[] ciphertext = new byte[cipher.getOutputSize(plaintext.length)]
    int contentLength = cipher.update(plaintext, 0, plaintext.length, ciphertext, 0)
    contentLength += cipher.doFinal(ciphertext, contentLength)
    project.gradleCrypto.ciphertextLength = contentLength
    project.gradleCrypto.plaintextLength = plaintext.length
    project.gradleCrypto.ciphertext = ciphertext
    project.gradleCrypto.iv = cipher.IV
    project.gradleCrypto.key = key.encoded
  }

  byte[] decrypt (byte[] ciphertext, int ciphertextLength, int plaintextLength, SecretKeySpec key, IvParameterSpec iv) {
    cipher.init(Cipher.DECRYPT_MODE, key, iv)
    byte[] plaintext = new byte[cipher.getOutputSize(ciphertextLength)]
    int contentLength = cipher.update(ciphertext, 0, ciphertextLength, plaintext, 0)
    contentLength += cipher.doFinal(plaintext, contentLength)
    plaintext[0..plaintextLength - 1] as byte[]
  }
}

class CryptoPluginEncryptTask extends CryptoPluginBaseTask {
  @TaskAction
  def encrypt() {
    SecretKeySpec key = generateKey()
    encrypt(project.gradleCrypto.plaintext, key)
  }

  SecretKeySpec generateKey () {
    int size = 16
    byte[] bytes = new byte[size]
    SecureRandom secureRandom = new SecureRandom()
    secureRandom.nextBytes(bytes)
    createKeyFromBytes(bytes)
  }
}

class CryptoPluginDecryptTask extends CryptoPluginBaseTask {
  @TaskAction
  def decrypt() {
    Security.addProvider(new BouncyCastleProvider())
    cipher = Cipher.getInstance('AES/CBC/PKCS7Padding', 'BC')
    def key = createKeyFromBytes(project.gradleCrypto.key)
    def iv = new IvParameterSpec(project.gradleCrypto.iv)
    def ciphertext = project.gradleCrypto.ciphertext
    def ciphertextLength = project.gradleCrypto.ciphertextLength
    def plaintextLength = project.gradleCrypto.plaintextLength
    def plaintext = decrypt(ciphertext, ciphertextLength, plaintextLength, key, iv)
    project.gradleCrypto.plaintext = plaintext
  }
}
