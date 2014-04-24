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
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.InvalidAttributeException;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.SAMLParsingException;
import fr.paris.lutece.portal.service.util.AppLogService;

import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.metadata.RequestedAttribute;

import java.util.Iterator;
import java.util.List;


public class RequiredAttributesChecker implements SAMLChecker
{
    public void check( SAMLResponseManager responseManager )
        throws InvalidAttributeException, SAMLParsingException
    {
        List<Attribute> assertionAttributes = responseManager.getAssertionAttributes(  );

        List<RequestedAttribute> requestedAttributes = BootStrap.getInstance(  ).getSpMetaDataManager(  )
                                                                .getRequestedAttributes(  );

        // Verification des attributs requis
        Iterator<RequestedAttribute> iterReq = requestedAttributes.listIterator(  );
        RequestedAttribute requestedAttribute;

        while ( iterReq.hasNext(  ) )
        {
            requestedAttribute = iterReq.next(  );

            if ( requestedAttribute.isRequired(  ) )
            {
                boolean found = false;
                Iterator<Attribute> iter = assertionAttributes.listIterator(  );
                Attribute assertionAttribute;

                while ( iter.hasNext(  ) )
                {
                    assertionAttribute = iter.next(  );

                    if ( assertionAttribute.getName(  ).equalsIgnoreCase( requestedAttribute.getName(  ) ) )
                    {
                        found = true;

                        break;
                    }
                }

                if ( !found )
                {
                    String message = "L'attribut obligatoire [" + requestedAttribute.getName(  ) +
                        "] est absent de l'assertion.";
                    AppLogService.info( message );
                    throw new InvalidAttributeException( message );
                }
            }
        }
    }
}
