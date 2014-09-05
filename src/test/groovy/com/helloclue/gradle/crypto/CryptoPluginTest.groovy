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
  }

  @Test
  void gradleCryptoPluginAddsGradleCryptoExtensionToProject() {
    Project project = ProjectBuilder.builder().build()
    project.apply plugin: 'gradle-crypto'
    assertNotNull(project.gradleCrypto)
  }

  @Test
  void gradleCryptoPluginEncryptsFile() {
    Project project = ProjectBuilder.builder().build()
    project.apply plugin: 'gradle-crypto'
    def plaintext = new File('src/test/resources/hodor.txt').getText()
    project.gradleCrypto.plaintext = plaintext
    project.tasks.encrypt.execute()
    assertNotNull(project.gradleCrypto.ciphertext)
    assertNotNull(project.gradleCrypto.ciphertextLength)
    assertNotNull(project.gradleCrypto.key)
    assertNotNull(project.gradleCrypto.iv)
    assertNotNull(project.gradleCrypto.plaintextLength)
  }

  @Test
  void gradleCryptoPluginDecryptsFile() {
    Project project = ProjectBuilder.builder().build()
    project.apply plugin: 'gradle-crypto'
    def plaintext = new File('src/test/resources/hodor.txt').getText()
    project.gradleCrypto.plaintext = plaintext
    project.tasks.encrypt.execute()
    project.gradleCrypto.plaintext = null
    project.tasks.decrypt.execute()
    new File("src/test/resources/hodor.out").withWriter { out ->
      out.println project.gradleCrypto.plaintext
    }
    assertEquals(project.gradleCrypto.plaintext, plaintext)
  }
}
