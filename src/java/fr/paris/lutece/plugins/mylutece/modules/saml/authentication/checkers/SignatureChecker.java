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
package fr.paris.lutece.plugins.mylutece.modules.saml.authentication.checkers;

import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.engine.BootStrap;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.engine.SAMLResponseManager;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.SAMLParsingException;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.SignatureValidationException;
import fr.paris.lutece.portal.service.util.AppLogService;

import org.opensaml.common.xml.SAMLConstants;

import org.opensaml.saml2.metadata.IDPSSODescriptor;

import org.opensaml.security.MetadataCriteria;
import org.opensaml.security.SAMLSignatureProfileValidator;

import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.validation.ValidationException;


public class SignatureChecker implements SAMLChecker
{
    public void check( SAMLResponseManager responseManager )
        throws SignatureValidationException, SAMLParsingException
    {
        // XML Validation
        SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator(  );

        try
        {
            profileValidator.validate( responseManager.getAssertion(  ).getSignature(  ) );
        }
        catch ( ValidationException e )
        {
            String message = "Erreur lors de la validation du sch�ma de la signature : " + e.getLocalizedMessage(  );
            AppLogService.info( message );
            throw new SignatureValidationException( message );
        }

        CriteriaSet criteriaSet = new CriteriaSet(  );
        criteriaSet.add( new EntityIDCriteria( responseManager.getAssertion(  ).getIssuer(  ).getValue(  ) ) );
        criteriaSet.add( new MetadataCriteria( IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS ) );

        /*
         * criteriaSet.add(new KeyInfoCriteria(idpMetaDataManager.getMetaData()
         * .getIDPSSODescriptor(SAMLConstants.SAML20P_NS)
         * .getKeyDescriptors().get(0).getKeyInfo()));
         */

        // Verification signature technique + validation entityID et protocol
        // support via criteriaSet
        try
        {
            if ( !BootStrap.getInstance(  ).getTrustEngine(  )
                               .validate( responseManager.getAssertion(  ).getSignature(  ), criteriaSet ) )
            {
                String message = "Erreur lors de la validation de la signature";
                AppLogService.info( message );
                throw new SignatureValidationException( message );
            }
        }
        catch ( SecurityException e1 )
        {
            String message = "Erreur lors de la validation de la signature" + e1.getLocalizedMessage(  );
            AppLogService.info( message );
            throw new SignatureValidationException( message );
        }
        catch ( Exception e1 )
        {
            String message = "Erreur lors de la validation de la signature" + e1.getLocalizedMessage(  );
            AppLogService.info( message );
            throw new SignatureValidationException( message );
        }
    }
}
