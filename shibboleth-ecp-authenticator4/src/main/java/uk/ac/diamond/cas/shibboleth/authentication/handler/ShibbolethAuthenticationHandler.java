/*
 * Diamond Light Source Limited licenses this file to you 
 * under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the 
 * License.  You may obtain a copy of the License at the 
 * following location:
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 *  
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package uk.ac.diamond.cas.shibboleth.authentication.handler;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;

import javax.management.AttributeNotFoundException;
import javax.security.auth.login.FailedLoginException;
import javax.security.sasl.AuthenticationException;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import org.apache.http.HttpHost;

import org.jasig.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.jasig.cas.authentication.PreventedException;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.SimplePrincipal;

import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.Response;
import org.opensaml.ws.soap.client.SOAPClientException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;

import uk.ac.diamond.shibbolethecpauthclient.ShibbolethECPAuthClient;

/**
 * Shibboleth authentication handler. Tries to authenticate against an IdP
 * If requested, it consumes the returned SAML assertion on successful 
 * authentication, then updates the principal with the updated information
 * 
 * @author Stefan Paetow
 * @version $Revision$ $Date$
 * @since 4.0.0
 */
public class ShibbolethAuthenticationHandler extends AbstractUsernamePasswordAuthenticationHandler {

    /** 
     * Identifies the Shibboleth IdP to try and authenticate against. 
     */
    @NotNull
    private String IdP;

    /**
     * Identifies the Shibboleth SP we want to run ECP against. 
     */
    @NotNull
    private String SP;

    /**
     * Identifies the eventual principal in the SAML response.
     */
    private String attribute;

    /**
     * Identifies an optional proxy host to connect to the IdP and the SP with.
     */
    private String proxyHost;

    /**
     * Identifies an optional proxy port to use with the proxy host.
     */
    @Min(0)
    private int proxyPort;

    /**
     * Disables certificate checking, usually used with self-signed certificates. 
     */
    @NotNull
    private boolean disableCertCheck;

    @Override
    protected final Principal authenticateUsernamePasswordInternal(final String username, final String password)
            throws GeneralSecurityException, PreventedException {

        logger.debug("Attempting to authenticate {} at {}", username, IdP);

        try {
            // Initialise the library
            DefaultBootstrap.bootstrap();
            final BasicParserPool parserPool = new BasicParserPool();
            parserPool.setNamespaceAware(true);

            // Set proxy
            HttpHost proxy = null;
            logger.debug("Setting proxy");
            if ((this.proxyHost != null) && (!this.proxyHost.isEmpty())) {
                if (this.proxyPort == 0) {
                    proxy = new HttpHost(this.proxyHost, 8080);
                } else {
                	proxy = new HttpHost(this.proxyHost, this.proxyPort);
                }
            }
            logger.debug("Set proxy successfully");
            
            // Instantiate a copy of the client, try to authentication, catch any errors that occur
            ShibbolethECPAuthClient ecpClient = new ShibbolethECPAuthClient(proxy, this.IdP, 
            		this.SP, disableCertCheck);
        	Response response = ecpClient.authenticate(username, password);
            logger.debug("Successfully authenticated {}", username);

            // if the attribute is empty, we simply authenticate and return the username as principal
            if ((this.attribute == null) || (this.attribute.isEmpty()))
            {
            	return new SimplePrincipal(username);
            }

            // get the first assertion in the response. Any exceptions here are a problem
            List<Attribute> attributes = response.getAssertions().get(0)
            		// get the first (and should be only) attribute statement
                    .getAttributeStatements().get(0)
                    // get all attributes
                    .getAttributes();

            // if there are no attributes, we can't do a lookup.
            if (attributes.isEmpty()) {
                throw new AttributeNotFoundException("The Shibboleth Identity Provider at " +
                		this.IdP + " returned a SAML assertion with no attributes");
            }

            // trawl the attributes to check if we can find ours
            String lookupAttributeValue = null;
            boolean idFound = false;
            for (Attribute attribute : attributes) {
                if ((attribute.getName().equals(this.attribute)) ||
                    (attribute.getFriendlyName().equals(this.attribute))) {
                    idFound = true;
                    XMLObject attributeValue = attribute.getAttributeValues().get(0);
                    if (attributeValue instanceof XSString) {
                        lookupAttributeValue = ((XSString) attributeValue).getValue();
                    } else if (attributeValue instanceof XSAny) {
                        lookupAttributeValue = ((XSAny) attributeValue).getTextContent();
                    }
                    logger.debug("Attribute: " + this.attribute + ", value: " + lookupAttributeValue);
                    break;
                } // if getName()...
            } // for attribute...

            // Attribute was not found in the SAML statement
            if (!idFound) {
                throw new AttributeNotFoundException("The attribute " + 
                        this.attribute + " was not returned by the Shibboleth Identity Provider.");
            }
            
            logger.info("Authentication was successful. Credential {} mapped to {}", username, lookupAttributeValue);
            return new SimplePrincipal(lookupAttributeValue);
            
        } catch (final AttributeNotFoundException e) {
            logger.debug("AttributeNotFoundException raised: {}", e.toString());
            throw new FailedLoginException(e.toString());
        } catch (final AuthenticationException e) {
            logger.debug("AuthenticationException raised: {}", e.toString());
            throw new FailedLoginException(e.toString());
        } catch (final IOException e) {
            logger.debug("IOException raised: {}", e.toString());
            throw new PreventedException(e);
        } catch (final Exception e) {
            logger.debug("Exception raised: {}", e.toString());
            throw new PreventedException(e);
        }
    }

    /**
     * Identifies the eventual principal in the SAML response.
     * 
     * @param attribute string identifying the eventual principal in the SAML response.
     */
    public void setAttribute(final String attribute) {
        this.attribute = attribute;
    }

    /**
     * Identifies the Shibboleth IdP to try and authenticate against.
     * 
     * @param IdP string specifying the full IdP ECP URL to authenticate against.
     */
    public void setIdP(final String IdP) {
        this.IdP = IdP;
    }

    /**
     * Identifies the Shibboleth SP we want to run ECP against.
     * 
     * @param SP string specifying a Shibboleth-protected URL to initiate the authentication with. 
     */
    public void setSP(final String SP) {
        this.SP = SP;
    }

    /**
     * Identifies an optional proxy host to connect to the IdP and the SP with.
     * 
     * @param proxyHost string specifying the proxy host to connect with.
     */
    public void setProxyHost(final String proxyHost) {
        this.proxyHost = proxyHost;
    }

    /**
     * Identifies an optional proxy port to use with the proxy host.
     * 
     * @param proxyPort integer specifying the proxy port to connect with. 
     */
    public void setProxyPort(final int proxyPort) {
        this.proxyPort = proxyPort;
    }

    /**
     * Disables certificate checking, usually used with self-signed certificates.
     * 
     * @param disableCertCheck boolean specifying whether to disable certificate checking. 
     */
    public void setDisableCertCheck(final boolean disableCertCheck) {
        this.disableCertCheck = disableCertCheck;
    }
}
