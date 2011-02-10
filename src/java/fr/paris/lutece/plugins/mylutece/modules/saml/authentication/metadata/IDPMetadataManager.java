/*
 * Copyright (c) 2002-2009, Mairie de Paris
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
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.CertificateValidationException;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.SAMLParsingException;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.util.X509CertificateHelper;
import fr.paris.lutece.portal.service.util.AppLogService;

import org.opensaml.common.xml.SAMLConstants;

import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;

import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.X509Data;

import java.io.IOException;
import java.io.InputStream;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import java.util.ArrayList;
import java.util.List;


public class IDPMetadataManager extends MetadataManager
{
    public IDPMetadataManager(  )
    {
        loadIDPCertificateChain(  );
    }

    private void loadIDPCertificateChain(  )
    {
        // TODO not yet implemented
    }

    @Override
    public void loadMetadata( String inFilePath )
    {
        // IDP Metadata file path
        if ( inFilePath == null )
        {
            inFilePath = ConfigProperties.getInstance(  ).getProperty( Constants.IDP_METADATA_FILE_PROP );
        }

        InputStream stream = this.getClass(  ).getResourceAsStream( inFilePath );
        loadMetadata( stream );
    }

    @Override
    protected void validateContent(  ) throws SAMLParsingException
    {
        // metadonn�es devraient contenir un IDPSSODescriptor
        IDPSSODescriptor idpSSODescriptor = metaData.getIDPSSODescriptor( SAMLConstants.SAML20P_NS );

        if ( idpSSODescriptor == null )
        {
            String message = "Les metadonn�es devraient contenir un IDPSSODescriptor";
            AppLogService.info( message );
            throw new SAMLParsingException( message );
        }

        // IDPSSODescriptor devrait contenir un et un seul KeyDescriptor
        List<KeyDescriptor> keyDescriptor = idpSSODescriptor.getKeyDescriptors(  );

        if ( keyDescriptor.size(  ) != 1 )
        {
            String message = "L'IDPSSODescriptor devrait contenir un et un seul KeyDescriptor. Il en contient " +
                keyDescriptor.size(  );
            AppLogService.info( message );
            throw new SAMLParsingException( message );
        }

        // KeyInfo devrait contenir un et un seul X509Data
        List<X509Data> x509Data = keyDescriptor.get( 0 ).getKeyInfo(  ).getX509Datas(  );

        if ( x509Data.size(  ) != 1 )
        {
            String message = "Le KeyInfo devrait contenir un et un seul X509Data. Il en contient " + x509Data.size(  );
            AppLogService.info( message );
            throw new SAMLParsingException( message );
        }

        // X509Data devrait contenir un et un seul X509Certificate
        List<org.opensaml.xml.signature.X509Certificate> x509Certificate = x509Data.get( 0 ).getX509Certificates(  );

        if ( x509Certificate.size(  ) != 1 )
        {
            String message = "Le X509Data devrait contenir un et un seul X509Certificate";
            AppLogService.info( message );
            throw new SAMLParsingException( message );
        }
    }

    /**
     * Extraction du certificat des Metadonn�e IDP.
     *
     * @return List<X509Certificate> r�duite � un �l�ment normalement
     * @throws CertificateValidationException
     * @throws SAMLParsingException
     */
    public List<X509Certificate> getCertificateWhiteList(  )
        throws CertificateValidationException
    {
        List<X509Certificate> liste = new ArrayList<X509Certificate>(  );

        try
        {
            IDPSSODescriptor idpSSODescriptor = metaData.getIDPSSODescriptor( SAMLConstants.SAML20P_NS );
            List<KeyDescriptor> keyDescriptor = idpSSODescriptor.getKeyDescriptors(  );
            KeyInfo keyInfo = keyDescriptor.get( 0 ).getKeyInfo(  );
            List<X509Data> x509Data = keyInfo.getX509Datas(  );
            List<org.opensaml.xml.signature.X509Certificate> x509Certificate = x509Data.get( 0 ).getX509Certificates(  );
            String b64MetadataCert = x509Certificate.get( 0 ).getValue(  );

            liste.add( X509CertificateHelper.buildX509Cert( b64MetadataCert ) );
        }
        catch ( CertificateException e )
        {
            String message = "Erreur lors de la recuperation du certificat des Metadonn�es" +
                e.getLocalizedMessage(  );
            AppLogService.info( message );
            throw new CertificateValidationException( message );
        }
        catch ( IOException e )
        {
            String message = "Erreur lors de la recuperation du certificat des Metadonn�es" +
                e.getLocalizedMessage(  );
            AppLogService.info( message );
            throw new CertificateValidationException( message );
        }

        return liste;
    }
}
