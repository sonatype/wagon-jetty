/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.maven.wagon.providers.http;

import org.apache.maven.wagon.TransferFailedException;
import org.apache.maven.wagon.authentication.AuthenticationInfo;
import org.apache.maven.wagon.authorization.AuthorizationException;
import org.apache.maven.wagon.providers.http.JettyClientHttpWagon.WagonExchange;
import org.apache.maven.wagon.proxy.ProxyInfo;
import org.codehaus.plexus.util.IOUtil;
import org.eclipse.jetty.http.HttpFields;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.util.Enumeration;

class HttpConnectionHelper
{
    private JettyClientHttpWagon _wagon;

    private HttpURLConnection urlConnection;

    private Authenticator previousAuthenticator;

    private static Field theAuthenticator;

    HttpConnectionHelper( JettyClientHttpWagon wagon )
    {
        _wagon = wagon;
    }

    public void send( WagonExchange exchange )
    {
        URL url;

        try
        {
            StringBuilder urlBuilder = new StringBuilder();
            urlBuilder.append( exchange.getScheme().toString() );
            urlBuilder.append( "://" );
            urlBuilder.append( exchange.getAddress().toString() );
            urlBuilder.append( exchange.getURI().replace( "//", "/" ) );
            url = new URL( urlBuilder.toString() );
        }
        catch ( Exception e )
        {
            return;
        }

        try
        {
            String method = exchange.getMethod();

            Proxy proxy = setupConnection( url );

            if ( method.equalsIgnoreCase( "GET" ) )
            {
                doGet( url, proxy, exchange, true );
            }
            else if ( method.equalsIgnoreCase( "HEAD" ) )
            {
                doGet( url, proxy, exchange, false );
            }
            else if ( method.equalsIgnoreCase( "PUT" ) )
            {
                doPut( url, proxy, exchange );
            }
        }
        catch ( Exception e )
        {
        }
        finally
        {
            closeConnection();
        }
    }

    private void doGet( URL url, Proxy proxy, WagonExchange exchange, boolean doGet )
        throws Exception
    {
        urlConnection = (HttpURLConnection) url.openConnection( proxy );
        urlConnection.setRequestProperty( "Accept-Encoding", "gzip" );
        if ( !_wagon.getUseCache() )
        {
            urlConnection.setRequestProperty( "Pragma", "no-cache" );
        }

        addHeaders( urlConnection );

        if ( doGet )
        {
            urlConnection.setRequestMethod( "GET" );
        }
        else
        {
            urlConnection.setRequestMethod( "HEAD" );
        }

        int responseCode = urlConnection.getResponseCode();
        exchange.setResponseStatus( responseCode );
        if ( responseCode == HttpURLConnection.HTTP_FORBIDDEN || responseCode == HttpURLConnection.HTTP_UNAUTHORIZED )
        {
            throw new AuthorizationException( "Access denied to: " + url );
        }

        if ( doGet )
        {
            InputStream is = urlConnection.getInputStream();

            ByteArrayOutputStream content = new ByteArrayOutputStream();
            IOUtil.copy( is, content );
            exchange.setResponseContentBytes( content.toByteArray() );

            exchange.setContentEncoding( urlConnection.getContentEncoding() );
        }

        exchange.setLastModified( urlConnection.getLastModified() );
        exchange.setContentLength( urlConnection.getContentLength() );
    }

    private void doPut( URL url, Proxy proxy, WagonExchange exchange )
        throws TransferFailedException
    {
        try
        {
            urlConnection = (HttpURLConnection) url.openConnection( proxy );

            addHeaders( urlConnection );

            urlConnection.setRequestMethod( "PUT" );
            urlConnection.setDoOutput( true );

            InputStream source = exchange.getRequestContentSource();
            OutputStream out = urlConnection.getOutputStream();
            source.reset();
            IOUtil.copy( source, out );
            out.close();

            exchange.setResponseStatus( urlConnection.getResponseCode() );
        }
        catch ( IOException e )
        {
            throw new TransferFailedException( "Error transferring file", e );
        }
    }

    private void addHeaders( URLConnection urlConnection )
    {
        HttpFields httpHeaders = _wagon.getHttpHeaders();
        if ( httpHeaders != null )
        {
            for ( Enumeration<String> names = httpHeaders.getFieldNames(); names.hasMoreElements(); )
            {
                String name = names.nextElement();
                urlConnection.setRequestProperty( name, httpHeaders.getStringField( name ) );
            }
        }
    }

    private Proxy setupConnection( URL url )
    {
        previousAuthenticator = getDefaultAuthenticator();

        Proxy proxy = Proxy.NO_PROXY;

        final ProxyInfo proxyInfo = _wagon.getProxyInfo( "http", url.getHost() );
        if ( proxyInfo != null )
        {
            InetSocketAddress address = InetSocketAddress.createUnresolved( proxyInfo.getHost(), proxyInfo.getPort() );
            proxy = new Proxy( Proxy.Type.HTTP, address );
        }

        AuthenticationInfo authenticationInfo = _wagon.getAuthenticationInfo();
        final boolean hasProxyAuth = ( proxyInfo != null && proxyInfo.getUserName() != null );
        final boolean hasServerAuth = ( authenticationInfo != null && authenticationInfo.getUserName() != null );
        if ( hasProxyAuth || hasServerAuth )
        {
            Authenticator.setDefault( new Authenticator()
            {
                @Override
                protected PasswordAuthentication getPasswordAuthentication()
                {
                    if ( hasProxyAuth && RequestorType.PROXY.equals( getRequestorType() ) )
                    {
                        String password = "";
                        if ( proxyInfo.getPassword() != null )
                        {
                            password = proxyInfo.getPassword();
                        }
                        return new PasswordAuthentication( proxyInfo.getUserName(), password.toCharArray() );
                    }

                    if ( hasServerAuth && RequestorType.SERVER.equals( getRequestorType() ) )
                    {
                        String password = "";
                        AuthenticationInfo authenticationInfo = _wagon.getAuthenticationInfo();
                        if ( authenticationInfo.getPassword() != null )
                        {
                            password = authenticationInfo.getPassword();
                        }
                        return new PasswordAuthentication( authenticationInfo.getUserName(), password.toCharArray() );
                    }

                    return super.getPasswordAuthentication();
                }
            } );
        }
        else
        {
            Authenticator.setDefault( null );
        }

        return proxy;
    }

    private void closeConnection()
    {
        if ( urlConnection != null )
        {
            urlConnection.disconnect();
        }

        Authenticator.setDefault( previousAuthenticator );
    }

    static Authenticator getDefaultAuthenticator()
    {
        if ( theAuthenticator == null )
        {
            try
            {
                theAuthenticator = Authenticator.class.getDeclaredField( "theAuthenticator" );
                theAuthenticator.setAccessible( true );
            }
            catch ( Exception e )
            {
                // pity
            }
        }

        try
        {
            return (Authenticator) theAuthenticator.get( null );
        }
        catch ( Exception e )
        {
            return null;
        }
    }

}
