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
package fr.paris.lutece.plugins.mylutece.modules.saml.authentication;

import fr.paris.lutece.plugins.mylutece.authentication.PortalAuthentication;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.config.ConfigProperties;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.config.Constants;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.engine.SAMLTokenHandler;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.CertificateValidationException;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.InvalidAttributeException;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.SAMLCheckerException;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.SAMLParsingException;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.SAMLTokenExtractorException;
import fr.paris.lutece.plugins.mylutece.modules.saml.authentication.exceptions.SignatureValidationException;
import fr.paris.lutece.plugins.mylutece.modules.saml.service.SAMLPlugin;
import fr.paris.lutece.portal.service.security.LoginRedirectException;
import fr.paris.lutece.portal.service.security.LuteceUser;
import fr.paris.lutece.portal.service.util.AppLogService;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import javax.security.auth.login.LoginException;

import javax.servlet.http.HttpServletRequest;


public class SAMLAuthentication extends PortalAuthentication
{
    /**
     * This method create an anonymous user
     *
     * @return A LuteceUser object corresponding to an anonymous user
     */
    public LuteceUser getAnonymousUser(  )
    {
        return new SAMLUser( LuteceUser.ANONYMOUS_USERNAME, this );
    }

    /**
     * Gets the Authentification service name
     * @return The name of the authentication service
     */
    public String getAuthServiceName(  )
    {
        return this.getClass(  ).getName(  );
    }

    /**
     * Gets the Authentification type
     * @param request The HTTP request
     * @return The type of authentication
     */
    public String getAuthType( HttpServletRequest request )
    {
        return HttpServletRequest.BASIC_AUTH;
    }

    /**
     * Checks that the current user is associated to a given role
     * @param user The user
     * @param request The HTTP request
     * @param strRole The role name
     * @return Returns true if the user is associated to the role, otherwise false
     */
    public boolean isUserInRole( LuteceUser user, HttpServletRequest request, String strRole )
    {
        return true;
    }

    /**
     * Checks the login
     *
     * @param strUserName The username
     * @param strUserPassword The user's passord
     * @param request The HttpServletRequest
     *
     * @return A LuteceUser object corresponding to the login
     *
     * @throws LoginException If a Login error occured
     * @throws LoginRedirectException If the the login process should be redirected
     */
    public LuteceUser login( String strUserName, String strUserPassword, HttpServletRequest request )
        throws LoginException, LoginRedirectException
    {
        SAMLTokenHandler tokenHandler = new SAMLTokenHandler(  );
        SAMLUser user = null;

        try
        {
            // Check Token
            tokenHandler.checkSAMLResponse( request );

            // Create LuteceUser
            user = createSAMLUser( tokenHandler );
        }
        catch ( SignatureValidationException e )
        {
            AppLogService.error( e.getMessage(  ), e );
            throw new LoginException(  );
        }
        catch ( CertificateValidationException e )
        {
            AppLogService.error( e.getMessage(  ), e );
            throw new LoginException(  );
        }
        catch ( InvalidAttributeException e )
        {
            AppLogService.error( e.getMessage(  ), e );
            throw new LoginException(  );
        }
        catch ( SAMLTokenExtractorException e )
        {
            AppLogService.error( e.getMessage(  ), e );
            throw new LoginException(  );
        }
        catch ( SAMLParsingException e )
        {
            AppLogService.error( e.getMessage(  ), e );
            throw new LoginException(  );
        }
        catch ( SAMLCheckerException e )
        {
            AppLogService.error( e.getMessage(  ), e );
            throw new LoginException(  );
        }

        return user;
    }

    /**
     * logout the user
     * @param user The user
     */
    public void logout( LuteceUser user )
    {
    }

    private SAMLUser createSAMLUser( SAMLTokenHandler tokenHandler )
        throws SAMLParsingException
    {
        // Create LuteceUser
        SAMLUser user = new SAMLUser( tokenHandler.getLuteceUserName(  ), this );

        // Set LuteceUser infos
        Map<String, String> userInfos = tokenHandler.getLuteceUserProperties(  );
        Iterator<Entry<String, String>> it = userInfos.entrySet(  ).iterator(  );

        while ( it.hasNext(  ) )
        {
            Map.Entry<String, String> pairs = (Map.Entry<String, String>) it.next(  );
            user.setUserInfo( pairs.getKey(  ), pairs.getValue(  ) );
        }

        // Set User Groups
        Collection<String> groups = tokenHandler.getLuteceUserGroups(  );
        user.setGroups( groups );

        // Set User Role
        Collection<String> roles = new ArrayList<String>(  );
        roles.add( ConfigProperties.getInstance(  ).getProperty( Constants.LUTECE_USER_ROLE_PROP ) );
        user.setRoles( roles );

        AppLogService.info( "Cr�ation LuteceUser : Nom=" + user.getName(  ) );

        return user;
    }

    public String[] getRolesByUser( LuteceUser user )
    {
        return null;
    }

    /**
     * 
     *{@inheritDoc}
     */
	public String getName()
	{
		return SAMLPlugin.PLUGIN_NAME;
	}

	/**
	 * 
	 *{@inheritDoc}
	 */
	public String getPluginName()
	{
		return SAMLPlugin.PLUGIN_NAME;
	}
}
