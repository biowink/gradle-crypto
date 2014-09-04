#Gradle plugin for encrypting and decrypting files

##Example usage script

``
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
