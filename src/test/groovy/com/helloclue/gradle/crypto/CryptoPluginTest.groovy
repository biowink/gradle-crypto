package com.helloclue.gradle.crypto

import org.gradle.testfixtures.ProjectBuilder
import org.gradle.api.Project

import org.junit.Test
import static org.junit.Assert.*

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
    assertNotNull(project.tasks.encrypt.ext.result.ciphertext)
    assertNotNull(project.tasks.encrypt.ext.result.ciphertextLength)
    assertNotNull(project.tasks.encrypt.ext.result.key)
    assertNotNull(project.tasks.encrypt.ext.result.iv)
    assertNotNull(project.tasks.encrypt.ext.result.plaintextLength)
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
    project.tasks.decrypt.inputs.properties(project.tasks.encrypt.ext.result)
    project.tasks.decrypt.execute()
    assertArrayEquals(project.tasks.decrypt.result.plaintext, plaintext)
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
    assertEquals(2, project.tasks.encryptFiles.outputs.files.from.size())
    def secret = project.tasks.encryptFiles.ext.secrets['counting.txt']
    assertNotNull(secret.ciphertextPath)
    assertEquals(80, secret.ciphertextLength)
    assertNotNull(secret.key)
    assertNotNull(secret.iv)
    assertEquals(78, secret.plaintextLength)

    /* Cleanup */
    project.tasks.encryptFiles.outputs.files.from.each { f -> f.delete() }
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
    project.tasks.encryptFiles.outputs.files.from.each { f -> f.delete() }
  }
}
