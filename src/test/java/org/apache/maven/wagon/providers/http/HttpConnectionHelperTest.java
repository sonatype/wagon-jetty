package org.apache.maven.wagon.providers.http;

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

import java.net.Authenticator;

import org.apache.maven.wagon.authentication.AuthenticationInfo;
import org.apache.maven.wagon.providers.http.JettyClientHttpWagon.WagonExchange;
import org.apache.maven.wagon.proxy.ProxyInfo;
import org.apache.maven.wagon.repository.Repository;

import junit.framework.TestCase;

public class HttpConnectionHelperTest
    extends TestCase
{

    public void testProxyReset()
        throws Exception
    {
        String originalProxyHost = System.getProperty( "http.proxyHost" );
        String originalProxyPort = System.getProperty( "http.proxyPort" );
        String originalProxyExclusions = System.getProperty( "http.nonProxyHosts" );

        ProxyInfo proxy = new ProxyInfo();
        proxy.setHost( "invalid.host" );
        proxy.setPort( 8888 );
        proxy.setType( "http" );
        proxy.setNonProxyHosts( "non-proxied-host" );

        JettyClientHttpWagon wagon = new JettyClientHttpWagon();
        wagon.connect( new Repository( "id", "http://bad.host" ), proxy );

        HttpConnectionHelper helper = new HttpConnectionHelper( wagon );

        WagonExchange exchange = wagon.newExchange();
        exchange.setURL( "http://bad.host/test" );

        try
        {
            helper.send( exchange );
        }
        catch ( Exception e )
        {
            // ignore
        }

        assertEquals( originalProxyHost, System.getProperty( "http.proxyHost" ) );
        assertEquals( originalProxyPort, System.getProperty( "http.proxyPort" ) );
        assertEquals( originalProxyExclusions, System.getProperty( "http.nonProxyHosts" ) );
    }

    public void testAuthenticatorReset()
        throws Exception
    {
        Authenticator originalAuthenticator = new Authenticator()
        {
        };
        Authenticator.setDefault( originalAuthenticator );

        AuthenticationInfo auth = new AuthenticationInfo();
        auth.setUserName( "user" );
        auth.setPassword( "pass" );

        JettyClientHttpWagon wagon = new JettyClientHttpWagon();
        wagon.connect( new Repository( "id", "http://bad.host" ), auth );

        HttpConnectionHelper helper = new HttpConnectionHelper( wagon );

        WagonExchange exchange = wagon.newExchange();
        exchange.setURL( "http://bad.host/test" );

        try
        {
            helper.send( exchange );
        }
        catch ( Exception e )
        {
            // ignore
        }

        assertSame( originalAuthenticator, HttpConnectionHelper.getDefaultAuthenticator() );
    }

}
