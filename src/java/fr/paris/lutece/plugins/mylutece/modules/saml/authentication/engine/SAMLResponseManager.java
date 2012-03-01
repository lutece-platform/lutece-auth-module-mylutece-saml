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
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.config.Constants;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.CertificateValidationException;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.SAMLParsingException;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.util.X509CertificateHelper;
import fr.paris.lutece.portal.service.security.LuteceUser;
import fr.paris.lutece.portal.service.util.AppLogService;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.validator.ResponseSchemaValidator;
import org.opensaml.saml2.metadata.RequestedAttribute;

import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.validation.ValidationException;

import java.io.IOException;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;


public class SAMLResponseManager
{
    private Response response = null;

    /**
     *
     * @param response
     * @throws SAMLParsingException
     */
    public SAMLResponseManager( Response response ) throws SAMLParsingException
    {
        initialize( response );
    }

    /**
     * Initialise le manager avec la Response. Valide le sch�ma et le contenu de
     * la Response.
     *
     * @param response
     * @throws SAMLParsingException
     */
    public void initialize( Response response ) throws SAMLParsingException
    {
        if ( response == null )
        {
            String message = "La Response ne devrait pas �tre nulle";
            AppLogService.info( message );
            throw new SAMLParsingException( message );
        }

        this.response = response;

        // Validation Sch�ma
        this.validateResponseSchema(  );

        // Validation Sch�ma "metier"
        this.validateResponseContent(  );
    }

    /**
     * Validation du sch�ma Response
     *
     * @throws SAMLParsingException
     */
    private void validateResponseSchema(  ) throws SAMLParsingException
    {
        // XML Validation
        ResponseSchemaValidator validator = new ResponseSchemaValidator(  );

        try
        {
            validator.validate( response );
        }
        catch ( ValidationException e )
        {
            String message = "Erreur lors de la validation du sch�ma de la Response : " + e.getLocalizedMessage(  );
            AppLogService.info( message );
            throw new SAMLParsingException( message );
        }
    }

    /**
     * Validation du contenu "Metier" de la Response.
     *
     * @throws SAMLParsingException
     */
    private void validateResponseContent(  ) throws SAMLParsingException
    {
        // Response devrait contenir un attribut Destination
        String destination = response.getDestination(  );

        if ( destination == null )
        {
            String message = "La Response devrait contenir un attribut Destination";
            AppLogService.info( message );
            throw new SAMLParsingException( message );
        }

        // Response doit contenir une et une seule Assertion.  
        List<Assertion> assertions = response.getAssertions(  );

        if ( assertions.size(  ) != 1 )
        {
            String message = "La Response devrait contenir une et une seule Assertion. Elle en contient " +
                assertions.size(  );
            AppLogService.info( message );
            throw new SAMLParsingException( message );
        }

        // Assertion devrait contenir une Signature
        Signature signature = assertions.get( 0 ).getSignature(  );

        if ( signature == null )
        {
            String message = "L'Assertion devrait contenir une Signature";
            AppLogService.info( message );
            throw new SAMLParsingException( message );
        }

        // Signature devrait contenir un KeyInfo
        KeyInfo keyInfo = signature.getKeyInfo(  );

        if ( keyInfo == null )
        {
            String message = "La Signature devrait contenir un KeyInfo";
            AppLogService.info( message );
            throw new SAMLParsingException( message );
        }

        // KeyInfo devrait contenir un et un seul X509Data
        List<X509Data> x509Datas = keyInfo.getX509Datas(  );

        if ( x509Datas.size(  ) != 1 )
        {
            String message = "Le KeyInfo devrait contenir un et un seul X509Data. Il en contient " +
                x509Datas.size(  );
            AppLogService.info( message );
            throw new SAMLParsingException( message );
        }

        // X509Data devrait contenir un et un seul X509Certificate
        List<org.opensaml.xml.signature.X509Certificate> x509Certificates = x509Datas.get( 0 ).getX509Certificates(  );

        if ( x509Certificates.size(  ) != 1 )
        {
            String message = "Le X509Data devrait contenir un et un seul X509Certificate. Il en contient " +
                x509Certificates.size(  );
            AppLogService.info( message );
            throw new SAMLParsingException( message );
        }

        // Assertion doit contenir un Subject
        Subject subject = assertions.get( 0 ).getSubject(  );

        if ( subject == null )
        {
            String message = "L'Assertion devrait contenir un Subject";
            AppLogService.info( message );
            throw new SAMLParsingException( message );
        }

        // Subject doit contenir un SubjectConfirmation
        List<SubjectConfirmation> subjectConfirmation = subject.getSubjectConfirmations(  );

        if ( subjectConfirmation.size(  ) != 1 )
        {
            String message = "Le Subject devrait contenir un et un seul SubjectConfirmations. Il en contient " +
                subjectConfirmation.size(  );
            AppLogService.info( message );
            throw new SAMLParsingException( message );
        }

        // SubjectConfirmation doit contenir un SubjectConfirmationData		
        SubjectConfirmationData subjectConfirmationData = subjectConfirmation.get( 0 ).getSubjectConfirmationData(  );

        if ( subjectConfirmationData == null )
        {
            String message = "Le SubjectConfirmation devrait contenir un SubjectConfirmationData";
            AppLogService.info( message );
            throw new SAMLParsingException( message );
        }

        // SubjectConfirmationData doit contenir un Recipient, Address
        if ( ( subjectConfirmationData.getRecipient(  ) == null ) || ( subjectConfirmationData.getAddress(  ) == null ) )
        {
            String message = "Le SubjectConfirmationData ne contient pas tous les attributs requis";
            AppLogService.info( message );
            throw new SAMLParsingException( message );
        }

        // Assertion doit contenir un Conditions
        Conditions conditions = assertions.get( 0 ).getConditions(  );

        if ( conditions == null )
        {
            String message = "L'Assertion devrait contenir un Conditions";
            AppLogService.info( message );
            throw new SAMLParsingException( message );
        }

        // Conditions doit contenir un NotBefore et NotOnOrAfter
        if ( ( conditions.getNotBefore(  ) == null ) || ( conditions.getNotOnOrAfter(  ) == null ) )
        {
            String message = "Conditions devrait contenir un NotBefore et un NotOnOrAfter";
            AppLogService.info( message );
            throw new SAMLParsingException( message );
        }

        // Conditions doit contenir un AudienceRestriction
        List<AudienceRestriction> audienceRestr = conditions.getAudienceRestrictions(  );

        if ( audienceRestr.size(  ) != 1 )
        {
            String message = "Conditions devrait contenir un et un seul AudienceRestrictions. Il en contient " +
                audienceRestr.size(  );
            AppLogService.info( message );
            throw new SAMLParsingException( message );
        }

        // AudienceRestriction doit contenir un Audience
        List<Audience> audience = audienceRestr.get( 0 ).getAudiences(  );

        if ( audience.size(  ) != 1 )
        {
            String message = "AudienceRestriction devrait contenir un et un seul Audience. Il en contient " +
                audience.size(  );
            AppLogService.info( message );
            throw new SAMLParsingException( message );
        }

        // Assertion devrait contenir un et un seul AttributeStatement
        List<AttributeStatement> attributesStatements = assertions.get( 0 ).getAttributeStatements(  );

        if ( attributesStatements.size(  ) != 1 )
        {
            String message = "L'Assertion devrait contenir un et un seul AttributeStatement. Elle en contient " +
                attributesStatements.size(  );
            AppLogService.info( message );
            throw new SAMLParsingException( message );
        }
    }

    /**
     * Retourne la valeur de l'attribut. Suppose que l'attribut ne contienne
     * qu'un seul AttributeValue. Sinon, Exception...
     *
     * @param attribute
     * @return La valeur de l'attribut
     * @throws SAMLParsingException si l'attribut est multivalu�
     */
    private String getAttributeValue( Attribute attribute )
        throws SAMLParsingException
    {
        List<XMLObject> values = attribute.getAttributeValues(  );

        if ( values.size(  ) != 1 )
        {
            String message = "L'attribut devrait contenir une et une seule AttributeValue. Il en contient " +
                values.size(  );
            AppLogService.info( message );
            throw new SAMLParsingException( message );
        }

        XSString stringValue = ( (XSString) values.get( 0 ) );

        return stringValue.getValue(  );
    }

    /**
     * Retourne la liste des valeurs de l'attribut attribute.
     *
     * @param attribute
     * @return La liste des valeurs de l'attribut
     */
    private List<String> getAttributeValues( Attribute attribute )
    {
        List<String> result = new ArrayList<String>(  );
        List<XMLObject> values = attribute.getAttributeValues(  );
        Iterator<XMLObject> iter = values.listIterator(  );

        while ( iter.hasNext(  ) )
        {
            XSString stringValue = (XSString) iter.next(  );
            result.add( stringValue.getValue(  ) );
        }

        return result;
    }

    /**
     * Retourne la premi�re (et seule) Assertion
     *
     * @return
     * @throws SAMLParsingException
     */
    public Assertion getAssertion(  )
    {
        return response.getAssertions(  ).get( 0 );
    }

    /**
     * Retourne le certificat de signature de l'assertion
     *
     * @return
     * @throws CertificateValidationException
     * @throws SAMLParsingException
     */
    public X509Certificate getSignatureCertificate(  )
        throws SAMLParsingException
    {
        X509Certificate cert = null;
        KeyInfo keyInfo = this.getAssertion(  ).getSignature(  ).getKeyInfo(  );
        List<X509Data> x509Datas = keyInfo.getX509Datas(  );
        List<org.opensaml.xml.signature.X509Certificate> x509Certificates = x509Datas.get( 0 ).getX509Certificates(  );
        String b64ResponseCert = x509Certificates.get( 0 ).getValue(  );

        try
        {
            cert = X509CertificateHelper.buildX509Cert( b64ResponseCert );
        }
        catch ( CertificateException e )
        {
            String message = "Erreur lors de la recuperation du certificat de signature : " +
                e.getLocalizedMessage(  );
            AppLogService.info( message );
            throw new SAMLParsingException( message );
        }
        catch ( IOException e )
        {
            String message = "Erreur lors de la recuperation du certificat de signature : " +
                e.getLocalizedMessage(  );
            AppLogService.info( message );
            throw new SAMLParsingException( message );
        }

        return cert;
    }

    /**
     * Retourne la liste des attributs de l'assertion
     *
     * @return
     * @throws SAMLParsingException
     */
    public List<Attribute> getAssertionAttributes(  )
    {
        List<AttributeStatement> attributesStatements = getAssertion(  ).getAttributeStatements(  );

        return attributesStatements.get( 0 ).getAttributes(  );
    }

    /**
     * Retourne la liste des attributs de l'assertion valides vis-�-vis des
     * requestedAttributes.
     *
     * @param requestedAttributes
     * @return La liste des attributs
     */
    private List<Attribute> getFilteredAssertionAttributes( List<RequestedAttribute> requestedAttributes )
    {
        List<Attribute> attributes = this.getAssertionAttributes(  );

        List<Attribute> filteredAttributes = new ArrayList<Attribute>(  );
        Iterator<Attribute> iter = attributes.listIterator(  );
        Attribute attribute;

        while ( iter.hasNext(  ) )
        {
            attribute = iter.next(  );

            Iterator<RequestedAttribute> iterReq = requestedAttributes.listIterator(  );
            RequestedAttribute reqAttribute;

            while ( iterReq.hasNext(  ) )
            {
                reqAttribute = iterReq.next(  );

                if ( reqAttribute.getName(  ).equals( attribute.getName(  ) ) )
                {
                    filteredAttributes.add( attribute );

                    break;
                }
            }
        }

        return filteredAttributes;
    }

    /**
     * Retourne la Map des Name/Value des attributs monovalu�s de l'assertion valides
     * vis-�-vis des requestedAttributes.
     *
     * @param requestedAttributes
     * @return
     */
    public Map<String, String> getFilteredAssertionAttributesValues( List<RequestedAttribute> requestedAttributes )
    {
        List<Attribute> attributes = this.getFilteredAssertionAttributes( requestedAttributes );
        Map<String, String> attributesValues = new HashMap<String, String>(  );

        Iterator<Attribute> iter = attributes.listIterator(  );
        Attribute attribute;

        while ( iter.hasNext(  ) )
        {
            attribute = iter.next(  );
            attributesValues.put( attribute.getName(  ), this.getAttributeValues( attribute ).get( 0 ) );
        }

        return attributesValues;
    }

    /**
     * R�cupere la valeur de l'Attribut servant � construire le LuteceUserName
     * dans l'Assertion.
     *
     * @return Le LuteceUserName si trouv�, la valeur par d�faut sinon.
     * @throws SAMLParsingException
     */
    public String getLuteceUserName(  )
    {
        List<Attribute> attributes = this.getAssertionAttributes(  );
        Iterator<Attribute> iter = attributes.listIterator(  );
        Attribute attribute;

        while ( iter.hasNext(  ) )
        {
            attribute = iter.next(  );

            if ( attribute.getName(  )
                              .equals( ConfigProperties.getInstance(  )
                                                           .getProperty( Constants.LUTECE_USER_NAME_ATTRIBUTE_NAME_PROP ) ) )
            {
                try
                {
                    return this.getAttributeValue( attribute );
                }
                catch ( SAMLParsingException e )
                {
                    String message = "L'Attribut contenant le nom du LuteceUser ne devrait pas �tre multivalu�";
                    AppLogService.info( message );

                    return LuteceUser.ANONYMOUS_USERNAME;
                }
            }
        }

        return LuteceUser.ANONYMOUS_USERNAME;
    }

    /**
     * R�cupere les valeurs de l'Attribut servant � construire le LuteceUser
     * Groups dans l'Assertion .
     *
     * @return Le LuteceUserName si trouv�, la valeur par d�faut sinon.
     * @throws SAMLParsingException
     */
    public List<String> getLuteceUserGroups(  )
    {
        List<Attribute> attributes = this.getAssertionAttributes(  );
        Iterator<Attribute> iter = attributes.listIterator(  );
        Attribute attribute;

        while ( iter.hasNext(  ) )
        {
            attribute = iter.next(  );

            if ( attribute.getName(  )
                              .equals( ConfigProperties.getInstance(  )
                                                           .getProperty( Constants.LUTECE_USER_GROUPS_ATTRIBUTE_NAME_PROP ) ) )
            {
                return this.getAttributeValues( attribute );
            }
        }

        return new ArrayList<String>(  );
    }

    /**
     *
     * @return
     */
    public Response getResponse(  )
    {
        return response;
    }
}
