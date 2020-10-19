# Usage

To run the project first package it:

```
mvn clean package
```

Afterwards a runnable jar will be in the target folder. It can be run like this:

```
java -jar target/keygen.jar keystore keystore.jks 123456 alias "CN=www.bernardomg.com, O=bernardomg, OU=None, L=London, ST=England, C=UK"
```

To show additional commands:

```
java -jar target/keygen.jar -h
```

## Generating a Key Store

```
java -jar target/keygen.jar keystore keystore.jks 123456 alias "CN=www.bernardomg.com, O=bernardomg, OU=None, L=London, ST=England, C=UK"
```

## Generating a Symmetric Key Store

```
java -jar target/keygen.jar symmetric keystore.jceks PASS=123456 ALIAS=alias
```

## Defining Certificate Range

The -start and -end optional parameters can be used to defined the validity range of a certificate:

```
java -jar target/keygen.jar keystore keystore.jks 123456 alias "CN=www.bernardomg.com, O=bernardomg, OU=None, L=London, ST=England, C=UK" -start=2020-01-01 -end=2020-02-01
```
