package com.helloclue.gradle.crypto

import org.gradle.api.Project
import org.gradle.api.Plugin

import java.security.Security
import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec
import javax.crypto.Cipher

import org.bouncycastle.jce.provider.BouncyCastleProvider

/**
 * @author pelle
 * Created: Wed Sep 03 15:26:28 CEST 2014
 */
class CryptoPlugin implements Plugin<Project> {

  Cipher cipher

  void apply (Project project) {
    Security.addProvider(new BouncyCastleProvider())
    cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC")

    project.task('encrypt') << {
      SecretKeySpec key = generateKey()
      def plainText = 'password' as byte[]
      println "plainText: " + plainText.encodeHex()
      def cipherText = encrypt(plainText, key)
      println "cipherText: " + cipherText.encodeHex()
    }
  }

  byte[] encrypt (byte[] plainText, SecretKeySpec key) {
    cipher.init(Cipher.ENCRYPT_MODE, key)
    byte[] cipherText = new byte[cipher.getOutputSize(plainText.length)]
    int contentLength = cipher.update(plainText, 0, plainText.length, cipherText, 0)
    contentLength += cipher.doFinal(cipherText, contentLength)
    cipherText
  }

  static SecretKeySpec generateKey () {
    int size = 16
    byte[] bytes = new byte[size]
    SecureRandom secureRandom = new SecureRandom()
    secureRandom.nextBytes(bytes)
    println "key: " + bytes.encodeHex()
    def key = new SecretKeySpec(bytes, "AES")
    key
  }
}

