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
package fr.paris.lutece.plugins.mylutece.modules.saml.authentication.config;

import fr.paris.lutece.portal.service.util.AppException;
import fr.paris.lutece.portal.service.util.AppLogService;
import fr.paris.lutece.portal.service.util.AppPropertiesService;

import java.io.FileNotFoundException;
import java.io.IOException;

import java.util.Map;
import java.util.Properties;


public class ConfigProperties extends Properties
{
    private static final long serialVersionUID = 6091203931131546429L;
    private static ConfigProperties instance = null;
    private boolean isTest = false;

    protected ConfigProperties(  )
    {
        try
        {
            init( "mylutece-saml-test.properties" );
        }
        catch ( FileNotFoundException ex )
        {
            String message = "File not found : " + ex.getMessage(  );
            AppLogService.error( message );
            throw new AppException( message, ex );
        }
        catch ( IOException ex )
        {
            String message = "Read error : " + ex.getMessage(  );
            AppLogService.error( message );
            throw new AppException( message, ex );
        }
    }

    public boolean isTest(  )
    {
        return instance.isTest;
    }

    public void setTest( boolean isTest )
    {
        instance.isTest = isTest;
    }

    public static void init(  ) throws Exception
    {
        if ( instance == null )
        {
            instance = new ConfigProperties(  );
        }
    }

    public static ConfigProperties getInstance(  )
    {
        if ( instance == null )
        {
            instance = new ConfigProperties(  );
        }

        return instance;
    }

    private void init( String name ) throws IOException
    {
        load( getClass(  ).getResourceAsStream( name ) );
        expandVariables(  );
    }

    @Override
    public String getProperty( String key, String defaultValue )
    {
        if ( isTest )
        {
            return super.getProperty( key, defaultValue );
        }
        else
        {
            return AppPropertiesService.getProperty( key, defaultValue );
        }
    }

    @Override
    public String getProperty( String key )
    {
        if ( isTest )
        {
            return super.getProperty( key );
        }
        else
        {
            return AppPropertiesService.getProperty( key );
        }
    }

    /**
     * Expands ${var} using System properties.
     */
    private void expandVariables(  )
    {
        for ( Map.Entry<Object, Object> e : this.entrySet(  ) )
        {
            String value = (String) e.getValue(  );

            boolean replaced;

            do
            {
                replaced = false;

                // Replace ${<varkey>} with <varval>
                int begin = 0;

                // Replace ${<varkey>} with <varval>
                int end = 0;

                if ( ( begin = value.indexOf( "${" ) ) != -1 )
                {
                    end = value.indexOf( '}', begin );

                    String varkey = value.substring( begin + 2, end );
                    String varval = System.getProperty( varkey );

                    if ( varval != null )
                    {
                        value = value.substring( 0, begin ) + varval + value.substring( end + 1 );
                        replaced = true;
                    }
                }
            }
            while ( replaced );

            if ( !value.equals( (String) e.getValue(  ) ) )
            {
                e.setValue( value );
            }
        }
    }
}
