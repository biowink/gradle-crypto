#Gradle plugin for encrypting and decrypting
A [Gradle](http://www.gradle.org/) plugin that exposes the tasks:

* `encrypt`,
* `decrypt`,
* `encryptFiles`,
* `decryptFiles`

These tasks uses the cryptographic algorithm [AES](http://en.wikipedia.org/wiki/Advanced_Encryption_Standard) (with [CBC](http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher-block_chaining_.28CBC.29) and [PKCS7Padding](http://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7)) to encrypt or decrypt.

##How it works
Once you've applied the `gradle-crypto` plugin you will have access to these tasks in your project. TaskInput and TaskOutput is used for transferring data back and forth to the tasks.

###Applying the plugin

```groovy
buildscript {
  repositories {
    mavenLocal()
    mavenCentral()
  }

  dependencies {
    classpath 'com.biowink.clue.gradle.crypto:gradle-crypto:1.0'
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
    classpath 'com.biowink.clue.gradle.crypto:gradle-crypto:1.0'
  }
}

apply plugin: 'gradle-crypto'

project.tasks.encrypt.inputs.property('plaintext', "Hodor! Hodor, hodor?".bytes)
project.tasks.encrypt.doLast {
    println "project.tasks.encrypt.ext.secret.ciphertext: ${project.tasks.encrypt.ext.secret.ciphertext}"
    println "project.tasks.encrypt.ext.secret.ciphertextLength: ${project.tasks.encrypt.ext.secret.ciphertextLength}"
    println "project.tasks.encrypt.ext.secret.key: ${project.tasks.encrypt.ext.secret.key}"
    println "project.tasks.encrypt.ext.secret.iv: ${project.tasks.encrypt.ext.secret.iv}"
    println "project.tasks.encrypt.ext.secret.plaintextLength: ${project.tasks.encrypt.ext.secret.plaintextLength}"
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
    classpath 'com.biowink.clue.gradle.crypto:gradle-crypto:1.0'
  }
}

apply plugin: 'gradle-crypto'

project.tasks.decrypt.inputs.properties([
  ciphertext: [61, 55, 120, 55, 93, 105, -50, 104, 0, -20, 73, -75, -107, 127, -111, 118, 58, -85, -74, 62, 100, -14, 52, 52, -74, -27, 125, 70, 20, 28, -108, -93] as byte[],
  ciphertextLength: 32,
  iv: [120, 11, 53, -81, 37, 52, 17, -88, -92, -84, -127, 105, -88, 55, 83, -128] as byte[],
  key: [-112, 124, -54, -125, 99, -29, -24, 17, 38, -62, 98, 101, 8, -17, -120, 20] as byte[],
  plaintextLength: 20,
])

project.tasks.decrypt.doLast {
    println "project.tasks.decrypt.ext.plaintext: ${new String(project.tasks.decrypt.ext.plaintext)}"
}
```
Run the encrypt task via `gradle decrypt`

##Test
Just run `gradle test`
