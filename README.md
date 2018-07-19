# Multi Authority Selective Disclosure Credentials System
This repository contains the code created for my final year project at University College London as part of the COMPM091 module. 

The project is developed entirely in JavaScript using React for client-side application and Node.js for server-side services. All the code relies on Milagro (https://github.com/milagro-crypto/milagro-crypto-js) library as a base for the cryptographic primitves. 

### Project Abstract
Credential systems allow users to obtain certifications for some messages and later prove possession of the obtained credentials to other parties in the system. Majority of them rely on digital signatures as a basic building block for required protocols. However, the established schemes have shortcomings. They either do not provide adequate privacy to create an anonymous system, that is a system in which actions of a particular user cannot be linked together, produce signatures which sizes heavily depend on amount of embedded information or allow only a single signer to be present, thus allowing for a single point of potential failure and compromise.

This project investigates the existing solutions and proposes an alternative signature scheme addressing their shortcomings. It allows for signing committed messages and uses signature randomization in order to introduce the required unlinkability. Furthermore, size of credentials is constant and relatively short regardless of the number of attributes embedded and the number of authorities that participated in its issuance.

The Tangerine credential system is implemented as a sample application of the scheme in an e-cash setting in the web environment. It manages to operate with reasonably low latency and scales well with different number of signing authorities present. However, as the number of simultaneous clients increases, the bottleneck of the system is discovered that originates from the issuer.

**Full thesis available upon request.**

### Architecture Diagram of the System:
![Diagram](https://i.imgur.com/Fclsj2O.png)

### Client Interface:
![Interface](https://i.imgur.com/4Y4C3UO.png)

### Running the system:

To run the system locally one can use the provided `startservers.sh` script that starts appropriate services in separate `tmux` windows. However, it requires that that all dependencies were already installed. This includes:
- running `npm install` and `npm build` within servers directory
- running `npm install` within client's directory
- installing docker
- creating SQL schema:

```
npm install knex -g

knex migrate:latest
```

