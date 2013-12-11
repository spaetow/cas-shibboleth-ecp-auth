cas-shibboleth-ecp-auth
=======================

CAS support for Shibboleth ECP Authentication against a single IdP 

This repository contains a CAS 4.0 extension for Shibboleth authentication.

It contains:

    ShibbolethAuthenticationHandler - An extension of AbstractUsernamePasswordAuthenticationHandler
      - It initiates an authentication conversation with a Shibboleth SP, then uses that to 
        authenticate against the IdP.
      - Property "attribute", when not null, identifies which SAML attribute to use as principal,
        otherwise the username entered is used.
        
Prerequisites
-------------

All dependencies will be available from Maven Central.

Usage
-----

Use the authentication handler in deployerConfigContext.xml:

    <bean id="primaryAuthenticationHandler"
          class="uk.ac.diamond.cas.shibboleth.authentication.handler.ShibbolethAuthenticationHandler">
        <property name="IdP" value="https://idp-host.domain.org/idp/profile/SAML2/SOAP/ECP" />
		<property name="SP" value="https://shibboleth-secured.domain.org/secure" />
		<property name="disableCertCheck" value="true" />
		<!-- the following 3 properties are optional -->
		<property name="attribute" value="attribute-to-act-as-principal" />
		<property name="proxyHost" value="proxy-host.domain.org" />
		<property name="proxyPort" value="8080" />
	</bean>

Add the following dependency to pom.xml for your CAS distribution:

	CAS 4.0.0:
	
    <dependency>
      <groupId>uk.ac.diamond</groupId>
      <artifactId>diamond-cas4-shibboleth-support</artifactId>
      <version>0.1.0</version>
    </dependency>

This is still a work in progress.
