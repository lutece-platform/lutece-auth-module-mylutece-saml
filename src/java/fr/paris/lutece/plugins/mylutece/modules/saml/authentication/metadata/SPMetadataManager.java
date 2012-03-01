/*
 * Copyright (c) 2002-2012, Mairie de Paris
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice
 *     and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice
 *     and the following disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *
 *  3. Neither the name of 'Mairie de Paris' nor 'Lutece' nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * License 1.0
 */
package fr.paris.lutece.plugins.mylutece.modules.saml.authentication.metadata;

import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.config.ConfigProperties;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.config.Constants;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.SAMLParsingException;

import org.apache.log4j.Logger;

import org.opensaml.common.xml.SAMLConstants;

import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml2.metadata.RequestedAttribute;
import org.opensaml.saml2.metadata.SPSSODescriptor;

import java.io.InputStream;

import java.util.List;


public class SPMetadataManager extends MetadataManager
{
    private static Logger _logger = Logger.getLogger( IDPMetadataManager.class );

    @Override
    public void loadMetadata( String inFilePath )
    {
        // IDP Metadata file path
        if ( inFilePath == null )
        {
            inFilePath = ConfigProperties.getInstance(  ).getProperty( Constants.SP_METADATA_FILE_PROP );
        }

        InputStream stream = this.getClass(  ).getResourceAsStream( inFilePath );
        loadMetadata( stream );
    }

    /**
     *
     * @throws SAMLParsingException
     */
    protected void validateContent(  ) throws SAMLParsingException
    {
        // metadonn�es devraient contenir un SPSSODescriptor
        SPSSODescriptor spSSODescriptor = metaData.getSPSSODescriptor( SAMLConstants.SAML20P_NS );

        if ( spSSODescriptor == null )
        {
            String message = "Les metadonn�es devraient contenir un SPSSODescriptor";
            _logger.warn( message );
            throw new SAMLParsingException( message );
        }

        // SPSSODescriptor devraient contenir un et un seul AttributeConsumingService
        List<AttributeConsumingService> attributeConsumingService = spSSODescriptor.getAttributeConsumingServices(  );

        if ( attributeConsumingService.size(  ) != 1 )
        {
            String message = "SPSSODescriptor devraient contenir un et un seul AttributeConsumingService";
            _logger.warn( message );
            throw new SAMLParsingException( message );
        }

        // SPSSODescriptor devraient contenir un et un seul AssertionConsumerServices
        List<AssertionConsumerService> assertionConsumerService = spSSODescriptor.getAssertionConsumerServices(  );

        if ( assertionConsumerService.size(  ) != 1 )
        {
            String message = "SPSSODescriptor devraient contenir un et un seul AssertionConsumerServices";
            _logger.warn( message );
            throw new SAMLParsingException( message );
        }
    }

    /**
     * Retourne la liste des attributs de la Metadonn�es
     * @return
     * @throws SAMLParsingException
     */
    public List<RequestedAttribute> getRequestedAttributes(  )
        throws SAMLParsingException
    {
        return getAttributeConsumingService(  ).getRequestAttributes(  );
    }

    private SPSSODescriptor getSPSSODescriptor(  )
    {
        return metaData.getSPSSODescriptor( SAMLConstants.SAML20P_NS );
    }

    private AttributeConsumingService getAttributeConsumingService(  )
    {
        return getSPSSODescriptor(  ).getAttributeConsumingServices(  ).get( 0 );
    }

    public AssertionConsumerService getAssertionConsumerService(  )
    {
        return getSPSSODescriptor(  ).getAssertionConsumerServices(  ).get( 0 );
    }
}
