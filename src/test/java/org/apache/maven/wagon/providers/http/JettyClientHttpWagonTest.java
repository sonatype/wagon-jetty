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
import org.mortbay.jetty.Request;
import org.mortbay.jetty.handler.AbstractHandler;
import org.mortbay.jetty.servlet.Context;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Properties;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class JettyClientHttpWagonTest
    extends HttpWagonTestCase
{

    @Override
    protected String getProtocol()
    {
        return "http";
    }

    @Override
    protected void setHttpHeaders( StreamingWagon wagon, Properties properties )
    {
        ( (JettyClientHttpWagon) wagon ).setHttpHeaders( properties );
    }

    public void testGetRedirectFromHttpToHttps()
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        SslRedirectHandler handler = new SslRedirectHandler();
        handlers = new Handler[] { handler };
        contexts = new Context[] {};
        connectors = new Connector[] { newHttpsConnector(), newHttpConnector() };

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        handler.httpsPort = server.getConnectors()[0].getLocalPort();

        StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try
        {
            wagon.getToStream( "/base.txt", out );

            assertEquals( "PASSED", out.toString( "UTF-8" ) );
            assertEquals( 1, handler.redirects );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    private static class SslRedirectHandler
        extends AbstractHandler
    {

        int httpsPort;

        int redirects;

        public void handle( String target, HttpServletRequest request, HttpServletResponse response, int dispatch )
            throws IOException, ServletException
        {
            if ( ( (Request) request ).isHandled() )
            {
                return;
            }

            if ( request.getServerPort() != httpsPort )
            {
                String url = "https://" + request.getServerName() + ":" + httpsPort + request.getRequestURI();

                response.setStatus( HttpServletResponse.SC_MOVED_PERMANENTLY );
                response.setHeader( "Location", url );

                redirects++;
            }
            else
            {
                response.getWriter().write( "PASSED" );
            }

            ( (Request) request ).setHandled( true );
        }
    }

}
