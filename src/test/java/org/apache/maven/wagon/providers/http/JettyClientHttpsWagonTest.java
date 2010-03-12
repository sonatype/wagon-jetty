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

import org.apache.maven.wagon.StreamingWagon;
import org.apache.maven.wagon.repository.Repository;
import org.mortbay.jetty.Connector;
import org.mortbay.jetty.Handler;
import org.mortbay.jetty.servlet.Context;

import java.io.ByteArrayOutputStream;
import java.util.Properties;

public class JettyClientHttpsWagonTest
    extends HttpWagonTestCase
{
    @Override
    protected String getProtocol()
    {
        return "https";
    }

    @Override
    protected void setHttpHeaders( StreamingWagon wagon, Properties properties )
    {
        ( (JettyClientHttpWagon) wagon ).setHttpHeaders( properties );
    }

    public void testClientAuthenticationWithCertificates()
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        handlers = new Handler[] { new StatusHandler( 200 ) };
        contexts = new Context[] {};
        connectors = new Connector[] { newHttpsConnector( true ) };

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        Properties props = System.getProperties();

        try
        {
            System.setProperty( "javax.net.ssl.keyStore", getTestFile( "src/test/resources/ssl/client-store" ).getAbsolutePath() );
            System.setProperty( "javax.net.ssl.keyStorePassword", "client-pwd" );
            System.setProperty( "javax.net.ssl.keyStoreType", "jks" );
            System.setProperty( "javax.net.ssl.trustStore", getTestFile( "src/test/resources/ssl/keystore" ).getAbsolutePath() );
            System.setProperty( "javax.net.ssl.trustStorePassword", "storepwd" );
            System.setProperty( "javax.net.ssl.trustStoreType", "jks" );

            StreamingWagon wagon = (StreamingWagon) getWagon();

            wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

            try
            {
                wagon.getToStream( "/base.txt", new ByteArrayOutputStream() );
            }
            finally
            {
                wagon.disconnect();

                tearDownWagonTestingFixtures();

                stopTestServer();
            }
        }
        finally
        {
            System.setProperties( props );
        }
    }

}
