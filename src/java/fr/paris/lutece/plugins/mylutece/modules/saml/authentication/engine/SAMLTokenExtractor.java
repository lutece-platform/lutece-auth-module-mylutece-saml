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
package fr.paris.lutece.plugins.mylutece.modules.saml.authentication.engine;

import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.config.Constants;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.SAMLTokenExtractorException;
import fr.paris.lutece.portal.service.util.AppLogService;

import org.opensaml.Configuration;

import org.opensaml.saml2.core.Response;

import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.util.Base64;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.StringReader;
import java.io.UnsupportedEncodingException;

import javax.servlet.http.HttpServletRequest;


public class SAMLTokenExtractor implements Constants
{
    /**
     * M�thode de construction de la SAMLResponse � partir d'une string XML
     *
     * @param xmlToken
     * @throws SAMLTokenExtractorException
     */
    public static Response extractSAMLResponse( HttpServletRequest request )
        throws SAMLTokenExtractorException
    {
        Response response = null;

        // Extraction de la SAMLResponse de la requete HTTP
        String SAMLResponseB64Str = request.getParameter( SAML_RESPONSE_REQUEST_PARAM );

        // Decodage URL encoding et Base64
        String SAMLResponseStr = null;

        try
        {
            SAMLResponseStr = new String( Base64.decode( SAMLResponseB64Str ), "UTF-8" );
        }
        catch ( UnsupportedEncodingException e1 )
        {
            String message = "Mauvais encodage de la Response : " + e1.getLocalizedMessage(  );
            AppLogService.info( message );
            throw new SAMLTokenExtractorException( message );
        }

        // Get parser pool manager
        BasicParserPool ppMgr = new BasicParserPool(  );
        ppMgr.setNamespaceAware( true );

        Document inCommonMDDoc;

        try
        {
            inCommonMDDoc = ppMgr.parse( new StringReader( SAMLResponseStr ) );

            Element ResponseRoot = inCommonMDDoc.getDocumentElement(  );

            // Get apropriate unmarshaller
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory(  );
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller( ResponseRoot );

            // Unmarshall using the document root element, an EntitiesDescriptor
            // in this case
            response = (Response) unmarshaller.unmarshall( ResponseRoot );
        }
        catch ( XMLParserException e )
        {
            String message = "Erreur de parsing de la SAMLResponse : " + e.getLocalizedMessage(  );
            AppLogService.info( message );
            throw new SAMLTokenExtractorException( message );
        }
        catch ( UnmarshallingException e )
        {
            String message = "Erreur de unmarshalling de la SAMLResponse : " + e.getLocalizedMessage(  );
            AppLogService.info( message );
            throw new SAMLTokenExtractorException( message );
        }

        return response;
    }
}
