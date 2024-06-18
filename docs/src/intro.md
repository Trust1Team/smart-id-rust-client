# Introduction

This document describes the relying party service interface protocol of Smart-ID server and
provides information for integration. The interface offers the entry point to Smart-ID main use
cases, i.e. authentication and signing.

The interface is to be used by relaying parties - parties who wish to use Smart-ID services,
i.e. ask end users to perform authentication and signing operations.

## 1.1 Glossary

* Smart-ID account - A person has to register a Smart-ID account to use services provided by the Smart-ID
  system. Account binds a Smart-ID app instance (installed on a person's mobile device)
  to a person's identity in the Smart-ID system. In the course of account creation and
  registration, the identity of the account owner (person) is proofed by a Registration
  Authority (RA) and the relation between the identity and a key pair is certified by a
  Certificate Authority (CA). An account has a signature key pair and an authentication
  key pair.
* Smart-ID app - A technical component of the Smart-ID system. A mobile app instance installed on a
  person's mobile device that provides access to Smart-ID functionality for persons.
* Smart-ID provider - An organization that is legally responsible for the Smart-ID system.
* Smart-ID server - A technical component of the Smart-ID system. Server-side counterpart of the Smart-ID
  app. Handles backend operations and provides API-s to Relying Party (RP).
* Smart-ID system - A technical and organizational environment, which enables digital authentication and
  issuing of digital signatures of persons in an electronic environment. The Smart-ID
  system provides services that allow persons (Smart-ID account owners) to authenticate
  themselves to RPs, to give digital signatures requested by RPs, and to manage their
  Smart-ID accounts.
* Authentication key pair (or authentication key) - Key pair, which is used to digitally authenticate a person.
* Certificate Authority (CA) - An entity that issues certificates for Smart-ID account owners.
* Key pair - Pair of keys, which are required for digital signature scheme. There are two kinds of key
  pairs (or shortly, keys) in the Smart-ID system, authentication key pair and signature key
  pair. The word pair refers to to the private and public keys of each key pair used in an
  assymetric cryptographic algorithm, here RSA.
* Mobile device - A tablet computer or smartphone that runs a mobile device operating system (Apple iOS,
  Google Android).
* Person - A natural person who uses the Smart-ID system to authenticate herself to an RP and to
  issue digital signatures requested by RP.
* Registration Authority (RA) - An entity responsible for recording or verifying some or all of the information (particularly
  the identities of subjects) needed by a CA to issue certificates and CRLs and to perform
  other certificate management functions.
* Relying Party (RP) - An organization or service, for example a bank, which is using the Smart-ID service to
  authenticate its users and to get them to sign the documents.
* Relying Party request - A request from an RP that requires some kind of operation in the Smart-ID backend
  system. It may or may not create a transaction.
* Signature key pair (or signature key) - Key pair, which is used to give digital signatures of a person.

## 1.2 Implementation References

> [Demo and Testing documentation](https://github.com/SK-EID/smart-id-documentation/wiki/Smart-ID-demo)
> 
> [Technical Parameters for Testing](https://github.com/SK-EID/smart-id-documentation/wiki/Environment-technical-parameters#accounts)
> 
> [Smart-ID External API](https://github.com/SK-EID/smart-id-documentation)
> 
> [Technical documentation](https://github.com/SK-EID/smart-id-documentation/wiki/Technical-overview)
>

## 1.3 Informative References

* **ETSI319412-1** ETSI. Electronic Signatures and Infrastructures (ESI); Certificate Profiles;
  Part 1: Overview and common data structures. 2015. URL: <http://www.etsi.org/deliver/etsi_en/319400_319499/31941201/01.01.00_30/en_31941201v010100v.pdf>.
* **rfc2616** R. Fielding et al. Hypertext Transfer Protocol – HTTP/1.1. RFC 2616 (Draft Standard).
  Obsoleted by RFCs 7230, 7231, 7232, 7233, 7234, 7235, updated by RFCs 2817, 5785,
  6266, 6585. Internet Engineering Task Force, June 1999. URL: <https://tools.ietf.org/html/rfc2616>.
* **rfc4122** P. Leach, M. Mealling, and R. Salz. A Universally Unique IDentifier (UUID) URN
  Namespace. RFC 4122 (Standards Track). Internet Engineering Task Force, July 2005.
  URL: <https://tools.ietf.org/html/rfc4122>.
* **rfc4648** S. Josefsson. The Base16, Base32, and Base64 Data Encodings. RFC 4648
  (Proposed Standard). Internet Engineering Task Force, Oct. 2006. URL: <https://tools.ietf.org/html/rfc4648>.