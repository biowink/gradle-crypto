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
  void gradleCryptoPluginEncryptsFile() {
    Project project = ProjectBuilder.builder().build()
    project.apply plugin: 'gradle-crypto'
    def plaintext = null
    new File('src/test/resources/startup.txt').withInputStream { is ->
      plaintext = is.bytes
    }
    project.tasks.encrypt.inputs.property('plaintext', plaintext)
    project.tasks.encrypt.execute()
    assertNotNull(project.tasks.encrypt.ext.result.ciphertext)
    assertNotNull(project.tasks.encrypt.ext.result.ciphertextLength)
    assertNotNull(project.tasks.encrypt.ext.result.key)
    assertNotNull(project.tasks.encrypt.ext.result.iv)
    assertNotNull(project.tasks.encrypt.ext.result.plaintextLength)
  }

  @Test
  void gradleCryptoPluginDecryptsFile() {
    Project project = ProjectBuilder.builder().build()
    project.apply plugin: 'gradle-crypto'
    def plaintext = null
    new File('src/test/resources/counting.txt').withInputStream { is ->
      plaintext = is.bytes
    }
    project.tasks.encrypt.inputs.property('plaintext', plaintext)
    project.tasks.encrypt.execute()
    project.tasks.decrypt.inputs.properties(project.tasks.encrypt.ext.result)
    println project.tasks.encrypt.ext.result
    project.tasks.decrypt.execute()
    /* new File('src/test/resources/counting.txt.out').withOutputStream { os -> */
    /*   os.write(project.gradleCrypto.plaintext) */
    /* } */
    assertArrayEquals(project.tasks.decrypt.result.plaintext, plaintext)
  }
}
