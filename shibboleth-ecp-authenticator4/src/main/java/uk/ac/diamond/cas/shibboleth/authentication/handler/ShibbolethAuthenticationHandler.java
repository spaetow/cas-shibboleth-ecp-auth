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
 * Shibboleth authentication handler. Tries a list of IdPs to authenticate against
 * It consumes the returned SAML assertion on successful authentication, then updates 
 * the Credentials with the updated information
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
    private int proxyPort;

    @Override
    protected final Principal authenticateUsernamePasswordInternal(final String username, final String password)
            throws GeneralSecurityException, PreventedException {

        logger.debug("Attempting to authenticate {} at {}", username, IdP);

        String lookupAttributeValue = null;

        try {
            // Initialise the library
            DefaultBootstrap.bootstrap();
            final BasicParserPool parserPool = new BasicParserPool();
            parserPool.setNamespaceAware(true);

            // reset proxy port to the default 8080
            if ((!this.proxyHost.isEmpty()) && (this.proxyPort == 0)) {
            	this.proxyPort = 8080;
            }

            // Instantiate a copy of the client, try to authentication, catch any errors that occur
            ShibbolethECPAuthClient ecpClient = new ShibbolethECPAuthClient(new HttpHost(this.proxyHost, this.proxyPort), this.IdP, 
            		this.SP, false);

            // if the attribute is empty, we simply authenticate and return the username as principal
            if (this.attribute.isEmpty())
            {
            	Response response = ecpClient.authenticate(username, password);
                logger.debug("Successfully authenticated {}", username);
            	return new SimplePrincipal(username);
            }
            
            // if we get an exception here with our 'chained' get(...) calls, we have a problem anyway!
            List<Attribute> attributes = ecpClient.authenticate(username, password)
            		// get the first (and should be only) assertion 
            		.getAssertions().get(0)
            		// get the first (and should be only) attribute statement
                    .getAttributeStatements().get(0)
                    // get all attributes
                    .getAttributes();

            // if there are no attributes, we can't do a lookup.
            if (attributes.isEmpty()) {
                throw new AttributeNotFoundException("The Shibboleth Identity Provider at " +
                		this.IdP + " returned a SAML assertion with no attributes");
            }

            logger.debug("Successfully authenticated {}", username);
            // trawl the attributes to check if we can find ours
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
                        this.attribute + " was not returned by the Shibboleth Identity Provider at " +
                		this.IdP);
            }
            
            logger.info("Authentication was successful. Credential {} mapped to {}", username, lookupAttributeValue);
            return new SimplePrincipal(lookupAttributeValue);
            
        } catch (final AttributeNotFoundException e) {
            throw new FailedLoginException(e.toString());
        } catch (final AuthenticationException e) {
            throw new FailedLoginException(e.toString());
        } catch (final Exception e) {
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
}
