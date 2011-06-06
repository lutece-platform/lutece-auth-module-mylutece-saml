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
package fr.paris.lutece.plugins.mylutece.modules.saml.authentication.engine;

import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.checkers.CertificateChecker;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.checkers.RequiredAttributesChecker;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.checkers.SAMLResponseChecker;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.checkers.SignatureChecker;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.SAMLCheckerException;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.SAMLParsingException;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.SAMLTokenExtractorException;
import fr.paris.lutece.portal.service.util.AppLogService;

import org.opensaml.saml2.core.Response;

import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;


public class SAMLTokenHandler
{
    private SAMLResponseManager responseManager = null;

    public SAMLTokenHandler(  )
    {
        BootStrap.init(  );
    }

    public void checkSAMLResponse( HttpServletRequest request )
        throws SAMLTokenExtractorException, SAMLParsingException, SAMLCheckerException
    {
        AppLogService.info( "D�but traitement Requ�te " + request.getRequestURL(  ) + " re�ue de " +
            request.getRemoteAddr(  ) );

        // Recuperation de la SAMLResponse
        Response response = SAMLTokenExtractor.extractSAMLResponse( request );
        responseManager = new SAMLResponseManager( response );

        // Validation signature
        SignatureChecker signatureChecker = new SignatureChecker(  );
        signatureChecker.check( responseManager );

        // Validation certificat vs IDP Metadonn�es
        CertificateChecker certificateChecker = new CertificateChecker(  );
        certificateChecker.check( responseManager );

        // Validation Attributs requis vs SP Metadonn�es
        RequiredAttributesChecker attributesChecker = new RequiredAttributesChecker(  );
        attributesChecker.check( responseManager );

        // Validation de l'assertion
        SAMLResponseChecker assertionChecker = new SAMLResponseChecker(  );
        assertionChecker.check( responseManager );
    }

    /**
     * Extraction du nom du LuteceUser a partir des Attributs de la
     * SAMLResponse. Le nom de l'Attribut a utiliser est donn� par la
     * configuration. Si l'Attribut n'est pas pr�sent dans l'Assertion, on
     * utilise un login anonyme.
     *
     * @return Le nom du LuteceUser
     * @throws SAMLParsingException
     */
    public String getLuteceUserName(  ) throws SAMLParsingException
    {
        return responseManager.getLuteceUserName(  );
    }

    /**
     * Extraction des userinfos du LuteceUser a partir des Attributs de la
     * SAMLResponse.
     *
     * @return Le nom du LuteceUser
     * @throws SAMLParsingException
     */
    public Map<String, String> getLuteceUserProperties(  )
        throws SAMLParsingException
    {
        return responseManager.getFilteredAssertionAttributesValues( BootStrap.getInstance(  ).getSpMetaDataManager(  )
                                                                              .getRequestedAttributes(  ) );
    }

    /**
     * Extraction du user groups du LuteceUser a partir des Attributs de la
     * SAMLResponse.
     *
     * @return Les groups du LuteceUser
     * @throws SAMLParsingException
     */
    public List<String> getLuteceUserGroups(  ) throws SAMLParsingException
    {
        return responseManager.getLuteceUserGroups(  );
    }
}
