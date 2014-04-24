/*
 * Copyright (c) 2002-2014, Mairie de Paris
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

import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.config.Constants;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.SAMLParsingException;
import fr.paris.lutece.portal.service.util.AppException;

import org.apache.log4j.Logger;

import org.opensaml.Configuration;

import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.validator.EntityDescriptorSchemaValidator;

import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.validation.ValidationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.InputStream;


public abstract class MetadataManager implements Constants
{
    private static Logger _logger = Logger.getLogger( MetadataManager.class );
    protected EntityDescriptor metaData = null;

    public MetadataManager(  )
    {
    }

    protected void loadMetadata( InputStream stream )
    {
        // Get parser pool manager
        BasicParserPool ppMgr = new BasicParserPool(  );
        ppMgr.setNamespaceAware( true );

        try
        {
            // Parse metadata file
            Document inCommonMDDoc = ppMgr.parse( stream );
            Element metadataRoot = inCommonMDDoc.getDocumentElement(  );

            // Get apropriate unmarshaller
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory(  );
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller( metadataRoot );

            // Unmarshall using the document root element, an EntitiesDescriptor
            // in this case
            metaData = (EntityDescriptor) unmarshaller.unmarshall( metadataRoot );
        }
        catch ( XMLParserException xe )
        {
            String message = "Erreur de parsing des metadonn�es " + xe.getLocalizedMessage(  );
            _logger.warn( message );
            throw new AppException( message, xe );
        }
        catch ( UnmarshallingException ue )
        {
            String message = "Erreur d'unmarshalling des metadonn�es " + ue.getLocalizedMessage(  );
            _logger.warn( message );
            throw new AppException( message, ue );
        }

        // Validation Sch�ma
        try
        {
            EntityDescriptorSchemaValidator schemaValidator = new EntityDescriptorSchemaValidator(  );
            schemaValidator.validate( metaData );
        }
        catch ( ValidationException e )
        {
            String message = "Erreur de validation des metadonn�es " + e.getLocalizedMessage(  );
            _logger.warn( message );
            throw new AppException( message, e );
        }

        // Validation contenu "Metier"
        try
        {
            this.validateContent(  );
        }
        catch ( SAMLParsingException e )
        {
            String message = "Erreur de validation des metadonn�es " + e.getLocalizedMessage(  );
            _logger.warn( message );
            throw new AppException( message, e );
        }
    }

    public abstract void loadMetadata( String inFilePath );

    protected abstract void validateContent(  ) throws SAMLParsingException;

    public EntityDescriptor getMetaData(  )
    {
        return metaData;
    }
}
