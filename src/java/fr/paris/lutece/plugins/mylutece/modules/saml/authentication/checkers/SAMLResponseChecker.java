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
package fr.paris.lutece.plugins.mylutece.modules.saml.authentication.checkers;

import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.engine.BootStrap;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.engine.SAMLResponseManager;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.SAMLCheckerException;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.SAMLParsingException;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.SAMLReponseCheckerException;
import fr.paris.lutece.portal.service.util.AppLogService;

import org.opensaml.saml2.core.StatusCode;


public class SAMLResponseChecker implements SAMLChecker
{
    public void check( SAMLResponseManager responseManager )
        throws SAMLCheckerException, SAMLParsingException
    {
        // Verifier Response/@Destination
        checkDestination( responseManager );

        ///Response/Status/StatusCode/@Value vs "urn:oasis:names:tc:SAML:2.0:status:Success"
        checkStatusCode( responseManager );

        // Verifier Assertion
        SAMLAssertionChecker assChecker = new SAMLAssertionChecker(  );
        assChecker.check( responseManager );
    }

    /**
     * Verifier Response/@Destination vs EntityDescriptor/SPSSODescriptor/AssertionConsumerService/@Location
     * @param responseManager
     * @throws SAMLParsingException
     * @throws SAMLReponseCheckerException
     */
    private void checkDestination( SAMLResponseManager responseManager )
        throws SAMLReponseCheckerException
    {
        String destination = responseManager.getResponse(  ).getDestination(  );

        String location = BootStrap.getInstance(  ).getSpMetaDataManager(  ).getAssertionConsumerService(  )
                                   .getLocation(  );

        if ( !destination.equals( location ) )
        {
            String message = "La Destination de la Response [" + destination +
                "] n'est pas valide vis-�-vis des m�tadonn�es [" + location + "]";
            AppLogService.info( message );
            throw new SAMLReponseCheckerException( message );
        }
    }

    /**
     * Verifier Response/Status/StatusCode/@Value vs "urn:oasis:names:tc:SAML:2.0:status:Success"
     * @param responseManager
     * @throws SAMLParsingException
     * @throws SAMLReponseCheckerException
     */
    private void checkStatusCode( SAMLResponseManager responseManager )
        throws SAMLParsingException, SAMLReponseCheckerException
    {
        String statusCode = responseManager.getResponse(  ).getStatus(  ).getStatusCode(  ).getValue(  );

        if ( !statusCode.equals( StatusCode.SUCCESS_URI ) )
        {
            String message = "Le StatusCode de la Response [" + statusCode + "] n'est pas [" + StatusCode.SUCCESS_URI +
                "]";
            AppLogService.info( message );
            throw new SAMLReponseCheckerException( message );
        }
    }
}
