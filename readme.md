# Keystore Generator

Keystore generator to be used for testing purposes. It generates a basic Java keystore.

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

More information, and instructions for other kinds of keystores, can be found in the documentation.

[![Release docs](https://img.shields.io/badge/docs-release-blue.svg)][site-release]
[![Development docs](https://img.shields.io/badge/docs-develop-blue.svg)][site-develop]

[![Release javadocs](https://img.shields.io/badge/javadocs-release-blue.svg)][javadoc-release]
[![Development javadocs](https://img.shields.io/badge/javadocs-develop-blue.svg)][javadoc-develop]

## Features

- Command Line Interface
- Generates JKS stores
- Generates symmetric JKS stores

## Documentation

Documentation is always generated for the latest release, kept in the 'master' branch:

- The [latest release documentation page][site-release].
- The [latest release Javadoc site][javadoc-release].

Documentation is also generated from the latest snapshot, taken from the 'develop' branch:

- The [the latest snapshot documentation page][site-develop].
- The [latest snapshot Javadoc site][javadoc-develop].

### Building the docs

The documentation site is actually a Maven site, and its sources are included in the project. If required it can be generated by using the following Maven command:

```
$ mvn verify site
```

## Usage

The application is embedded in a runnable JAR.

First package the project:

```
mvn clean package
```

Then run it like this:

```
java -jar target/keygen.jar keystore keystore.jks 123456 alias "CN=www.bernardomg.com, O=bernardomg, OU=None, L=London, ST=England, C=UK"
```

## Collaborate

Any kind of help with the project will be well received, and there are two main ways to give such help:

- Reporting errors and asking for extensions through the issues management
- or forking the repository and extending the project

### Issues management

Issues are managed at the GitHub [project issues tracker][issues], where any Github user may report bugs or ask for new features.

### Getting the code

If you wish to fork or modify the code, visit the [GitHub project page][scm], where the latest versions are always kept. Check the 'master' branch for the latest release, and the 'develop' for the current, and stable, development version.

## License

The project has been released under the [MIT License][license].

[issues]: https://github.com/bernardo-mg/keystore-generator/issues
[javadoc-develop]: https://docs.bernardomg.com/development/maven/keystore-generator/apidocs
[javadoc-release]: https://docs.bernardomg.com/maven/keystore-generator/apidocs
[license]: http://www.opensource.org/licenses/mit-license.php
[scm]: https://github.com/bernardo-mg/keystore-generator
[site-develop]: https://docs.bernardomg.com/development/maven/keystore-generator
[site-release]: https://docs.bernardomg.com/maven/keystore-generator
