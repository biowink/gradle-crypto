#Gradle plugin for encrypting and decrypting strings
A [Gradle](http://www.gradle.org/) plugin that exposes two tasks `encrypt` and `decrypt`.
These tasks uses the cryptographic algorithm [AES](http://en.wikipedia.org/wiki/Advanced_Encryption_Standard) (with [CBC](http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher-block_chaining_.28CBC.29) and [PKCS7Padding](http://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7)) to encrypt or decrypt strings.

##How it works
Once you've applied the `gradle-crypto` plugin you will have access to a new resource in your project. This resource is called `gradleCrypto` and is used for transferring data back and forth to the plugin.

###Applying the plugin

```groovy
buildscript {
  repositories {
    mavenLocal()
    mavenCentral()
  }

  dependencies {
    classpath 'com.helloclue.gradle.crypto:gradle-crypto:1.1'
  }
}

apply plugin: 'gradle-crypto'
```

###Encrypting a string
Create this `build.gradle`
```groovy
buildscript {
  repositories {
    mavenLocal()
    mavenCentral()
  }

  dependencies {
    classpath 'com.helloclue.gradle.crypto:gradle-crypto:1.1'
  }
}

apply plugin: 'gradle-crypto'

gradleCrypto {
  plaintext = "Hodor! Hodor, hodor?"
}

project.tasks.encrypt.doLast {
    println "project.gradleCrypto.ciphertext: ${project.gradleCrypto.ciphertext}"
    println "project.gradleCrypto.ciphertextLength: ${project.gradleCrypto.ciphertextLength}"
    println "project.gradleCrypto.key: ${project.gradleCrypto.key}"
    println "project.gradleCrypto.iv: ${project.gradleCrypto.iv}"
    println "project.gradleCrypto.plaintextLength: ${project.gradleCrypto.plaintextLength}"
}

```
Run the encrypt task via `gradle encrypt`


###Decrypt a string
Create this `build.gradle`
```groovy
buildscript {
  repositories {
    mavenLocal()
    mavenCentral()
  }

  dependencies {
    classpath 'com.helloclue.gradle.crypto:gradle-crypto:1.1'
  }
}

apply plugin: 'gradle-crypto'

gradleCrypto {
  ciphertext = "dZuX5azyPZ27xS1F7lUrcnzokps+efQ9P2VQSuOPIyI="
  ciphertextLength = 32
  key = "zuykuAYKC2vIWYTvZ+V1fw=="
  iv = "4GfBiB1IhcOTDWkYmfy3Jg=="
  plaintextLength = 20
}

project.tasks.decrypt.doLast {
    println "project.gradleCrypto.plaintext: ${project.gradleCrypto.plaintext}"
}

```
Run the encrypt task via `gradle decrypt`

##Test
Just run `gradle test`
