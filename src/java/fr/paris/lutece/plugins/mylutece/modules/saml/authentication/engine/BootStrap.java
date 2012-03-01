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

import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.config.ConfigProperties;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.metadata.IDPMetadataManager;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.metadata.SPMetadataManager;
import fr.paris.lutece.portal.service.util.AppException;
import fr.paris.lutece.portal.service.util.AppLogService;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;

import org.opensaml.saml2.metadata.provider.DOMMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;

import org.opensaml.security.MetadataCredentialResolver;

import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;


public class BootStrap
{
    private static BootStrap instance = null;
    private IDPMetadataManager idpMetaDataManager = null;
    private SPMetadataManager spMetaDataManager = null;
    private ExplicitKeySignatureTrustEngine trustEngine = null;

    protected BootStrap(  )
    {
        // Initialize the OpenSAML library
        try
        {
            DefaultBootstrap.bootstrap(  );
        }
        catch ( ConfigurationException e )
        {
            String message = "Erreur d'initialisation de OpenSAML" + e.getLocalizedMessage(  );
            AppLogService.error( message );
            throw new AppException( message, e );
        }

        // Initialize the configuration
        try
        {
            ConfigProperties.init(  );
        }
        catch ( Exception e )
        {
            String message = "Erreur d'initialisation des propri�t�s du plugin MyLutece-SAML" +
                e.getLocalizedMessage(  );
            AppLogService.error( message );
            throw new AppException( message, e );
        }

        // Initialisation des Metadonn�es
        initializeIDPMetaData( null );
        initializeSPMetaData( null );
    }

    public ExplicitKeySignatureTrustEngine getTrustEngine(  )
    {
        return trustEngine;
    }

    public IDPMetadataManager getIdpMetaDataManager(  )
    {
        return idpMetaDataManager;
    }

    public SPMetadataManager getSpMetaDataManager(  )
    {
        return spMetaDataManager;
    }

    public static void init(  )
    {
        if ( instance == null )
        {
            instance = new BootStrap(  );
        }
    }

    public static BootStrap getInstance(  )
    {
        return instance;
    }

    public void initializeIDPMetaData( String inFilePath )
    {
        // Initialize the MetaData
        // Recuperation des MetaData
        idpMetaDataManager = new IDPMetadataManager(  );
        idpMetaDataManager.loadMetadata( inFilePath );

        // Construction d'un MetaDataProvider a partir de ces MetaData
        DOMMetadataProvider mdProvider = new DOMMetadataProvider( idpMetaDataManager.getMetaData(  ).getDOM(  ) );

        try
        {
            mdProvider.initialize(  );
        }
        catch ( MetadataProviderException e )
        {
            String message = "Erreur d'initialisation des MetaDataProvider" + e.getLocalizedMessage(  );
            AppLogService.error( message );
            throw new AppException( message, e );
        }

        // Creation d'un MetadataCredentialResolver
        MetadataCredentialResolver mdCredResolver = new MetadataCredentialResolver( mdProvider );

        // Creation d'un KeyInfoCredentialResolver
        KeyInfoCredentialResolver keyInfoCredResolver = Configuration.getGlobalSecurityConfiguration(  )
                                                                     .getDefaultKeyInfoCredentialResolver(  );
        // Creation d'un ExplicitKeySignatureTrustEngine
        trustEngine = new ExplicitKeySignatureTrustEngine( mdCredResolver, keyInfoCredResolver );
    }

    public void initializeSPMetaData( String inFilePath )
    {
        // Initialize the MetaData
        spMetaDataManager = new SPMetadataManager(  );
        spMetaDataManager.loadMetadata( inFilePath );
    }
}
