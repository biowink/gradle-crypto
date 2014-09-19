package com.biowink.clue.gradle.crypto

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
    project.task('encryptFiles', type: CryptoPluginEncryptFilesTask)
    project.task('decryptFiles', type: CryptoPluginDecryptFilesTask)
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

  SecretKeySpec generateKey () {
    int size = 16
    byte[] bytes = new byte[size]
    SecureRandom secureRandom = new SecureRandom()
    secureRandom.nextBytes(bytes)
    createKeyFromBytes(bytes)
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
}

class CryptoPluginDecryptTask extends CryptoPluginBaseTask {
  @TaskAction
  void decrypt() {
    def key = createKeyFromBytes(inputs.properties.key)
    def iv = new IvParameterSpec(inputs.properties.iv)
    def ciphertext = inputs.properties.ciphertext
    def ciphertextLength = inputs.properties.ciphertextLength
    def plaintextLength = inputs.properties.plaintextLength
    ext.result = decrypt(ciphertext, ciphertextLength, plaintextLength, key, iv)
  }
}

class CryptoPluginEncryptFilesTask extends CryptoPluginBaseTask {
  @TaskAction
  void encryptFiles() {
    ext.secrets = [:]
    inputs.properties.plaintextFiles.each { file ->
      file.withInputStream { is ->
        def plaintext = is.bytes
        SecretKeySpec key = generateKey()
        def result = encrypt(plaintext, key)
        def ciphertextFile = File.createTempFile('enc.', '.enc', new File(file.parent))
        ciphertextFile.withOutputStream { os -> os.write(result.ciphertext) }
        outputs.file(ciphertextFile)
        ext.secrets[file.name] = [
          ciphertextPath: ciphertextFile.name,
          ciphertextLength: result.ciphertextLength,
          iv: result.iv,
          key: result.key,
          plaintextLength: result.plaintextLength,
        ]
      }
    }
  }
}

class CryptoPluginDecryptFilesTask extends CryptoPluginBaseTask {
  @TaskAction
  void decryptFiles() {
    inputs.properties.secrets.each { plaintextSecretMap ->
      def secret = plaintextSecretMap.value
      def key = createKeyFromBytes(secret.key)
      def iv = new IvParameterSpec(secret.iv)
      def ciphertext = null
      def ciphertextFile = new File(inputs.properties.directory + secret.ciphertextPath)
      ciphertextFile.withInputStream { is -> ciphertext = is.bytes }
      def plaintext = decrypt(ciphertext, secret.ciphertextLength, secret.plaintextLength, key, iv).plaintext
      def plaintextFilename = plaintextSecretMap.key
      def plaintextFile = new File(inputs.properties.directory + plaintextFilename)
      plaintextFile.withOutputStream { os -> os.write(plaintext) }
    }
  }
}
