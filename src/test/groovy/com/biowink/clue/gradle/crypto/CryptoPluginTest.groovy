package com.biowink.clue.gradle.crypto

import org.gradle.testfixtures.ProjectBuilder
import org.gradle.api.Project

import org.junit.Test
import static org.junit.Assert.*

/**
 * @author pelle
 * Created: Wed Sep 03 15:26:28 CEST 2014
 * Copyright 2014 Biowink GmbH
 */
class CryptoPluginTest {
  @Test
  void gradleCryptoPluginAddsEncryptTaskToProject() {
    Project project = ProjectBuilder.builder().build()
    project.apply plugin: 'gradle-crypto'
    assertNotNull(project.tasks.encrypt)
    assertNotNull(project.tasks.decrypt)
    assertNotNull(project.tasks.encryptFiles)
    assertNotNull(project.tasks.decryptFiles)
  }

  @Test
  void gradleCryptoPluginEncrypt() {
    Project project = ProjectBuilder.builder().build()
    project.apply plugin: 'gradle-crypto'
    def plaintext = '''
      abcdefghijklmnopqrstuvwxyzåäö
      ABCDEFGHIJKLMNOPQRSTUVWXYZÅÄÖ
      0123456789'''.bytes
    project.tasks.encrypt.inputs.property('plaintext', plaintext)
    project.tasks.encrypt.execute()
    assertNotNull(project.tasks.encrypt.ext.secret.ciphertext)
    assertNotNull(project.tasks.encrypt.ext.secret.ciphertextLength)
    assertNotNull(project.tasks.encrypt.ext.secret.key)
    assertNotNull(project.tasks.encrypt.ext.secret.iv)
    assertNotNull(project.tasks.encrypt.ext.secret.plaintextLength)
  }

  @Test
  void gradleCryptoPluginDecrypt() {
    Project project = ProjectBuilder.builder().build()
    project.apply plugin: 'gradle-crypto'
    def plaintext = '''
      abcdefghijklmnopqrstuvwxyzåäö
      ABCDEFGHIJKLMNOPQRSTUVWXYZÅÄÖ
      0123456789'''.bytes
    project.tasks.encrypt.inputs.property('plaintext', plaintext)
    project.tasks.encrypt.execute()
    project.tasks.decrypt.inputs.properties(project.tasks.encrypt.ext.secret)
    project.tasks.decrypt.execute()
    assertArrayEquals(project.tasks.decrypt.plaintext, plaintext)
  }

  @Test
  void gradleCryptoPluginEncryptFiles() {
    Project project = ProjectBuilder.builder().build()
    project.apply plugin: 'gradle-crypto'

    project.tasks.encryptFiles.inputs.property('plaintextFiles', [
      new File('src/test/resources/counting.txt'),
      new File('src/test/resources/startup.txt'),
    ])
    project.tasks.encryptFiles.execute()
    assertEquals(2, project.tasks.encryptFiles.ext.secrets.size())
    def secret = project.tasks.encryptFiles.ext.secrets['counting.txt']
    assertNotNull(secret.ciphertextPath)
    assertEquals(80, secret.ciphertextLength)
    assertNotNull(secret.key)
    assertNotNull(secret.iv)
    assertEquals(78, secret.plaintextLength)

    /* Cleanup */
    project.tasks.encryptFiles.ext.secrets.each { m -> new File('src/test/resources/' + m.value.ciphertextPath).delete() }
  }

  @Test
  void gradleCryptoPluginDecryptFiles() {
    Project project = ProjectBuilder.builder().build()
    project.apply plugin: 'gradle-crypto'

    def plaintextFile = new File('src/test/resources/counting.txt')
    def expectedPlaintext = plaintextFile.text
    project.tasks.encryptFiles.inputs.property('plaintextFiles', [
      plaintextFile,
      new File('src/test/resources/startup.txt'),
    ])
    project.tasks.encryptFiles.execute()

    project.tasks.decryptFiles.inputs.property('directory', 'src/test/resources/')
    project.tasks.decryptFiles.inputs.property('secrets', project.tasks.encryptFiles.ext.secrets)
    project.tasks.decryptFiles.execute()

    def actualPlaintext = new File('src/test/resources/counting.txt').text
    assertEquals(expectedPlaintext, actualPlaintext)

    /* Cleanup */
    project.tasks.encryptFiles.ext.secrets.each { m -> new File('src/test/resources/' + m.value.ciphertextPath).delete() }
  }
}
