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
    project.task('encrypt', type: CryptoPluginEncryptTask)
    project.task('decrypt', type: CryptoPluginDecryptTask)
  }
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

  Map encrypt (byte[] plaintext, SecretKeySpec key) {
    cipher.init(Cipher.ENCRYPT_MODE, key)
    byte[] ciphertext = new byte[cipher.getOutputSize(plaintext.length)]
    int contentLength = cipher.update(plaintext, 0, plaintext.length, ciphertext, 0)
    contentLength += cipher.doFinal(ciphertext, contentLength)
    [
      ciphertext: ciphertext,
      ciphertextLength: contentLength,
      iv: cipher.IV,
      key: key.encoded,
      plaintextLength: plaintext.length,
    ]
  }

  Map decrypt (byte[] ciphertext, int ciphertextLength, int plaintextLength, SecretKeySpec key, IvParameterSpec iv) {
    cipher.init(Cipher.DECRYPT_MODE, key, iv)
    byte[] plaintext = new byte[cipher.getOutputSize(ciphertextLength)]
    int contentLength = cipher.update(ciphertext, 0, ciphertextLength, plaintext, 0)
    contentLength += cipher.doFinal(plaintext, contentLength)
    plaintext = plaintext[0..plaintextLength - 1] as byte[]
    [
      plaintext: plaintext,
    ]
  }
}

class CryptoPluginEncryptTask extends CryptoPluginBaseTask {
  @TaskAction
  void encrypt() {
    SecretKeySpec key = generateKey()
    ext.result = encrypt(inputs.properties.plaintext, key)
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
  void decrypt() {
    Security.addProvider(new BouncyCastleProvider())
    cipher = Cipher.getInstance('AES/CBC/PKCS7Padding', 'BC')
    def key = createKeyFromBytes(inputs.properties.key)
    def iv = new IvParameterSpec(inputs.properties.iv)
    def ciphertext = inputs.properties.ciphertext
    def ciphertextLength = inputs.properties.ciphertextLength
    def plaintextLength = inputs.properties.plaintextLength
     ext.result = decrypt(ciphertext, ciphertextLength, plaintextLength, key, iv)
  }
}
