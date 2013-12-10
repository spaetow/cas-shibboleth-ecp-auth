cas-shibboleth-ecp-auth
=======================

CAS support for Shibboleth ECP Authentication against a single IdP 

This repository contains a CAS 4.0 extension for Shibboleth authentication.

It contains:

    ShibbolethAuthenticationHandler - An extension of the AbstractUsernamePasswordAuthenticationHandler
      - It initiates an authentication conversation with a Shibboleth SP, then uses that to authenticate 
        against the IdP.
      - Property "attribute", when not null, identifies which SAML attribute to use as principal,
        otherwise the username entered is used.
        
Prerequisites
-------------

All dependencies should be available from Maven Central.

Usage
-----

	CAS 4.0.0:  
	
    <dependency>
      <groupId>uk.ac.diamond</groupId>
      <artifactId>diamond-cas4-shibboleth-support</artifactId>
      <version>0.1.0</version>
    </dependency>


This is still a work in progress.
