/*
 * Copyright (c) 2002-2011, Mairie de Paris
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

import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.config.ConfigProperties;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.config.Constants;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.engine.BootStrap;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.engine.SAMLResponseManager;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.SAMLCheckerException;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.SAMLParsingException;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.SAMLReponseCheckerException;
import fr.paris.lutece.portal.service.util.AppLogService;

import org.joda.time.DateTime;


public class SAMLAssertionChecker implements SAMLChecker
{
    public void check( SAMLResponseManager responseManager )
        throws SAMLCheckerException, SAMLParsingException
    {
        // Verifier Assertion/Issuer
        checkIssuer( responseManager );

        // Verifier Assertion/Subject
        checkSubject( responseManager );

        // Verifier Assertion/Conditions
        checkConditions( responseManager );

        // Verifier Assertion/AuthnStatement
        // Rien?

        // Verifier Assertion/AttributeStatement
        // cf RequiredAttributes
    }

    /**
     * Verifier Assertion/Issuer vs EntityDescriptor/@entityID sur IDP
     * @param responseManager
     * @throws SAMLReponseCheckerException
     */
    private void checkIssuer( SAMLResponseManager responseManager )
        throws SAMLReponseCheckerException
    {
        String issuer = responseManager.getAssertion(  ).getIssuer(  ).getValue(  );
        String entityID = BootStrap.getInstance(  ).getIdpMetaDataManager(  ).getMetaData(  ).getEntityID(  );

        if ( !issuer.equals( entityID ) )
        {
            String message = "L'Issuer de l'Assertion [" + issuer + "] n'est conforme aux m�tadonn�es [" +
                entityID + "]";
            AppLogService.info( message );
            throw new SAMLReponseCheckerException( message );
        }
    }

    /**
     * Verifier Subject/SubjectConfirmation/SubjectConfirmationData/@Recipient vs /SPSSODescriptor/AssertionConsumerService/@Location
     * Subject/SubjectConfirmation/SubjectConfirmationData/@Recipient vs /SPSSODescriptor/AssertionConsumerService/@Location
     * Subject/SubjectConfirmation/SubjectConfirmationData/@NotOnOrAfter vs now + decalage
     * @param responseManager
     * @throws SAMLReponseCheckerException
     */
    private void checkSubject( SAMLResponseManager responseManager )
        throws SAMLReponseCheckerException
    {
        String recipient = responseManager.getAssertion(  ).getSubject(  ).getSubjectConfirmations(  ).get( 0 )
                                          .getSubjectConfirmationData(  ).getRecipient(  );
        String location = BootStrap.getInstance(  ).getSpMetaDataManager(  ).getAssertionConsumerService(  )
                                   .getLocation(  );

        if ( !recipient.equals( location ) )
        {
            String message = "Le Recipient de l'Assertion [" + recipient + "] n'est conforme aux m�tadonn�es [" +
                location + "]";
            AppLogService.info( message );
            throw new SAMLReponseCheckerException( message );
        }
    }

    /**
     * Verifier Conditions/NotBefore vs time
     * Verifier Conditions/NotOnOrAfter vs time
     * Verifier Conditions/AudienceRestriction/Audience vs /EntityDescriptor/@entityID sur SP
     * @param responseManager
     * @throws SAMLReponseCheckerException
     */
    private void checkConditions( SAMLResponseManager responseManager )
        throws SAMLReponseCheckerException
    {
        DateTime notAfter = responseManager.getAssertion(  ).getConditions(  ).getNotOnOrAfter(  );
        DateTime notBefore = responseManager.getAssertion(  ).getConditions(  ).getNotBefore(  );
        DateTime now = new DateTime(  );
        long allowedTimeShiftInMillis = 1000 * new Integer( ConfigProperties.getInstance(  )
                                                                            .getProperty( Constants.LUTECE_CLOCK_SKEW_PROP ) );

        if ( now.isAfter( notAfter.getMillis(  ) + allowedTimeShiftInMillis ) )
        {
            String message = "La dur�e de validit� de l'Assertion est expir�e";
            AppLogService.info( message );
            throw new SAMLReponseCheckerException( message );
        }

        if ( now.isBefore( notBefore.getMillis(  ) - allowedTimeShiftInMillis ) )
        {
            String message = "L'Assertion n'est pas encore valide";
            AppLogService.info( message );
            throw new SAMLReponseCheckerException( message );
        }

        String audience = responseManager.getAssertion(  ).getConditions(  ).getAudienceRestrictions(  ).get( 0 )
                                         .getAudiences(  ).get( 0 ).getAudienceURI(  );
        String entityID = BootStrap.getInstance(  ).getSpMetaDataManager(  ).getMetaData(  ).getEntityID(  );

        if ( !audience.equals( entityID ) )
        {
            String message = "L'Audience de l'Assertion [" + audience + "] n'est pas conforme aux m�tadonn�es [" +
                entityID + "]";
            AppLogService.info( message );
            throw new SAMLReponseCheckerException( message );
        }
    }
}
