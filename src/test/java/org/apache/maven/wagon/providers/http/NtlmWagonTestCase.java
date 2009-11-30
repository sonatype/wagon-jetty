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

import org.apache.maven.wagon.FileTestUtils;
import org.apache.maven.wagon.StreamingWagon;
import org.apache.maven.wagon.Wagon;
import org.apache.maven.wagon.authentication.AuthenticationInfo;
import org.apache.maven.wagon.events.TransferListener;
import org.apache.maven.wagon.observers.ChecksumObserver;
import org.apache.maven.wagon.observers.Debug;
import org.apache.maven.wagon.providers.http.JettyClientHttpWagon.WagonExchange;
import org.apache.maven.wagon.repository.Repository;
import org.apache.maven.wagon.repository.RepositoryPermissions;
import org.codehaus.plexus.PlexusTestCase;
import org.codehaus.plexus.util.FileUtils;
import org.codehaus.plexus.util.IOUtil;
import org.codehaus.plexus.util.StringInputStream;
import org.codehaus.plexus.util.StringOutputStream;
import org.easymock.AbstractMatcher;
import org.easymock.MockControl;
import org.eclipse.jetty.http.HttpMethods;
import org.mortbay.jetty.Connector;
import org.mortbay.jetty.Handler;
import org.mortbay.jetty.HttpConnection;
import org.mortbay.jetty.Request;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.handler.AbstractHandler;
import org.mortbay.jetty.security.Constraint;
import org.mortbay.jetty.security.ConstraintMapping;
import org.mortbay.jetty.security.HashUserRealm;
import org.mortbay.jetty.security.SecurityHandler;
import org.mortbay.jetty.servlet.Context;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public abstract class NtlmWagonTestCase
    extends PlexusTestCase
{
    private Server server;

    private Connector[] connectors;

    private Handler[] handlers;

    private Context[] contexts;

    public static final class ProgressArgumentMatcher
        extends AbstractMatcher
    {
        private int size;

        @Override
        protected boolean argumentMatches( Object expected, Object actual )
        {
            if ( actual instanceof byte[] )
            {
                return true;
            }
            if ( actual instanceof Integer )
            {
                size += ( (Integer) actual ).intValue();
                return true;
            }
            return super.argumentMatches( expected, actual );
        }

        public int getSize()
        {
            return size;
        }
    }

    protected static String POM = "pom.xml";

    protected Repository localRepository;

    protected Repository testRepository;

    protected String localRepositoryPath;

    protected File sourceFile;

    protected File destFile;

    protected String resource;

    protected File artifactSourceFile;

    protected File artifactDestFile;

    protected ChecksumObserver checksumObserver;

    protected TransferListener mockTransferListener;

    protected MockControl mockTransferListenerControl;

    // ----------------------------------------------------------------------
    // Constructors
    // ----------------------------------------------------------------------

    // protected void setUp()
    // throws Exception
    // {
    // checksumObserver = new ChecksumObserver();
    //    
    // mockTransferListenerControl = MockControl.createControl( TransferListener.class );
    // mockTransferListener = (TransferListener) mockTransferListenerControl.getMock();
    //    
    // super.setUp();
    // }

    /**
     * Protocol id of the Wagon to use, eg. <code>scp</code>, <code>ftp</code>
     * 
     * @return the protocol id
     */
    protected abstract String getProtocol();

    protected void setupTestServer()
        throws Exception
    {
        // stopTestServer();
        //
        // File repositoryDirectory = getRepositoryDirectory();
        // FileUtils.deleteDirectory( repositoryDirectory );
        // repositoryDirectory.mkdirs();
        //        
        // server = new Server( 0 );
        //        
        // addConnectors( server );
        // addHandlers( server );
        // addContexts( server );
        //
        // server.start();
    }

    protected void stopTestServer()
        throws Exception
    {
        // if (server != null)
        // {
        // server.stop();
        // server = null;
        // }
    }

    // protected void addConnectors( Server srv )
    // {
    // if ( connectors != null )
    // {
    // srv.setConnectors(connectors);
    // connectors = null;
    // }
    // if (getProtocol().equalsIgnoreCase("http"))
    // {
    // SelectChannelConnector connector = new SelectChannelConnector();
    // server.addConnector(connector);
    // }
    // else
    // {
    // SslSocketConnector connector = new SslSocketConnector();
    // String keystore = getTestFile("src/test/resources/ssl/keystore").getAbsolutePath();
    // connector.setPort(0);
    // connector.setKeystore(keystore);
    // connector.setPassword("storepwd");
    // connector.setKeyPassword("keypwd");
    // server.addConnector(connector);
    // }
    // }
    //    
    // protected void addHandlers( Server srv )
    // {
    // if ( handlers == null)
    // {
    // PutHandler putHandler = new PutHandler( getRepositoryPath() );
    // srv.addHandler( putHandler );
    // }
    // else
    // {
    // srv.setHandlers(handlers);
    // handlers = null;
    // }
    // }
    //
    // protected void addContexts( Server srv )
    // throws IOException
    // {
    // if ( contexts == null)
    // {
    // Context root = new Context( srv, "/", Context.SESSIONS );
    // root.setResourceBase( getRepositoryPath() );
    // ServletHolder servletHolder = new ServletHolder( new DefaultServlet() );
    // servletHolder.setInitParameter( "gzip", "true" );
    // root.addServlet( servletHolder, "/*" );
    // }
    // else
    // {
    // for (Context ctx : contexts)
    // {
    // srv.addHandler(ctx);
    // }
    // contexts = null;
    // }
    // }

    protected void setupRepositories()
        throws Exception
    {
        resource = "test-resource";

        testRepository = new Repository();
        testRepository.setUrl( getTestRepositoryUrl() );
        testRepository.setPermissions( getPermissions() );

        localRepositoryPath = getRepositoryPath();
        localRepository = createFileRepository( "file://" + localRepositoryPath );
        message( "Local repository: " + localRepository );
    }

    protected Repository createFileRepository( String url )
    {
        File path = new File( url.substring( 7 ) );

        path.mkdirs();

        Repository repository = new Repository();

        repository.setUrl( url );

        return repository;
    }

    protected File getRepositoryDirectory()
    {
        return getTestFile( "target/test-output/http-repository" );
    }

    protected String getRepositoryPath()
    {
        return getRepositoryDirectory().getAbsolutePath();
    }

    protected String getOutputPath()
    {
        return getTestFile( "target/test-output" ).getAbsolutePath();
    }

    protected String getTestRepositoryUrl()
    {
        // return getProtocol() + "://localhost:" + getLocalPort();
        // *TODO* return the URL of the test host
        return System.getProperty( "ntlm.host", "http://host.domain.com/" );
    }

    protected int getLocalPort()
    {
        // Connector[] cons = server.getConnectors();
        // return cons[cons.length-1].getLocalPort();
        return 80;
    }

    protected void setupWagonTestingFixtures()
        throws Exception
    {
    }

    protected void tearDownWagonTestingFixtures()
        throws Exception
    {
    }

    protected AuthenticationInfo getAuthInfo()
    {
        AuthenticationInfo authInfo = new AuthenticationInfo();
        authInfo.setUserName( "mgorovoy" );
        authInfo.setPassword( "webtide" );
        return authInfo;
    }

    protected RepositoryPermissions getPermissions()
    {
        return new RepositoryPermissions();
    }

    protected Wagon getWagon()
        throws Exception
    {
        Wagon wagon = (Wagon) lookup( Wagon.ROLE, getProtocol() );

        Debug debug = new Debug();

        wagon.addSessionListener( debug );

        wagon.addTransferListener( debug );

        return wagon;
    }

    protected void message( String message )
    {
        System.out.println( message );
    }

    protected void alert( String message )
    {
        System.err.println( message );
    }

    public void testHelperPut()
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        JettyClientHttpWagon wagon = (JettyClientHttpWagon) getWagon();
        wagon.setAuthInfo( getAuthInfo() );

        String resourceURL = getTestRepositoryUrl() + "/ntlm/helper-res.txt";
        WagonExchange exchange = wagon.newExchange();
        exchange.setURL( resourceURL );
        exchange.setMethod( HttpMethods.PUT );
        exchange.setResponseStatus( 100 );

        StringInputStream in = new StringInputStream( "test helper" );
        exchange.setRequestContentSource( in );

        HttpConnectionHelper helper = new HttpConnectionHelper( wagon );
        helper.send( exchange );

        int responseStatus = exchange.getResponseStatus();
        Set<Integer> success = new HashSet<Integer>( Arrays.asList( 200, 201 ) );
        assertTrue( success.contains( responseStatus ) );
    }

    public void testHelperGet()
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        JettyClientHttpWagon wagon = (JettyClientHttpWagon) getWagon();
        wagon.setAuthInfo( getAuthInfo() );

        String resourceURL = getTestRepositoryUrl() + "/ntlm/helper-res.txt";
        WagonExchange exchange = wagon.newExchange();
        exchange.setURL( resourceURL );
        exchange.setMethod( HttpMethods.GET );
        exchange.setResponseStatus( 100 );

        HttpConnectionHelper helper = new HttpConnectionHelper( wagon );
        helper.send( exchange );

        assertEquals( 200, exchange.getResponseStatus() );
    }

    public void testWagon()
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        String filepath = "ntlm/wagon-res.txt";
        String contents = "test wagon";
        putFile( filepath, filepath, contents );

        StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ), getAuthInfo() );

        StringOutputStream out = new StringOutputStream();
        try
        {
            boolean result = wagon.resourceExists( filepath );

            assertTrue( result );

            if ( result )
            {
                wagon.getToStream( filepath, out );
            }

            assertEquals( contents, out.toString() );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    protected void putFile( String resourceName, String testFileName, String content )
        throws Exception
    {
        sourceFile = new File( FileTestUtils.getTestOutputDir(), testFileName );
        sourceFile.getParentFile().mkdirs();
        FileUtils.fileWrite( sourceFile.getAbsolutePath(), content );

        Wagon wagon = getWagon();

        message( "Putting test artifact: " + resourceName + " into test repository " + testRepository );

        wagon.connect( testRepository, getAuthInfo() );

        wagon.put( sourceFile, resourceName );

        wagon.disconnect();
    }

    static class StatusHandler
        extends AbstractHandler
    {
        private int status;

        public void setStatusToReturn( int status )
        {
            this.status = status;
        }

        public void handle( String target, HttpServletRequest request, HttpServletResponse response, int dispatch )
            throws IOException, ServletException
        {
            if ( status != 0 )
            {
                response.setStatus( status );
                ( (Request) request ).setHandled( true );
            }
        }
    }

    static class PutHandler
        extends AbstractHandler
    {
        private final String resourcePath;

        public PutHandler( String repositoryPath )
        {
            this.resourcePath = repositoryPath;
        }

        public void handle( String target, HttpServletRequest request, HttpServletResponse response, int dispatch )
            throws IOException, ServletException
        {
            Request base_request =
                request instanceof Request ? (Request) request : HttpConnection.getCurrentConnection().getRequest();

            if ( base_request.isHandled() || !"PUT".equals( base_request.getMethod() ) )
            {
                return;
            }

            base_request.setHandled( true );

            File file = new File( resourcePath, URLDecoder.decode( request.getPathInfo() ) );
            file.getParentFile().mkdirs();
            FileOutputStream out = new FileOutputStream( file );
            ServletInputStream in = request.getInputStream();
            try
            {
                IOUtil.copy( in, out );
            }
            finally
            {
                in.close();
                out.close();
            }

            response.setStatus( HttpServletResponse.SC_CREATED );
        }
    }

    private static class TestHeaderHandler
        extends AbstractHandler
    {
        protected Map<String, String> headers;

        public TestHeaderHandler()
        {
        }

        @SuppressWarnings( "unchecked" )
        public void handle( String target, HttpServletRequest request, HttpServletResponse response, int dispatch )
            throws IOException, ServletException
        {
            headers = new HashMap<String, String>();
            for ( Enumeration e = request.getHeaderNames(); e.hasMoreElements(); )
            {
                String name = (String) e.nextElement();
                headers.put( name, request.getHeader( name ) );
            }

            response.setContentType( "text/plain" );
            response.setStatus( HttpServletResponse.SC_OK );
            response.getWriter().println( "Hello, World!" );

            ( (Request) request ).setHandled( true );
        }
    }

    private static class AuthorizingNtlmHandler
        extends AbstractHandler
    {
        public void handle( String target, HttpServletRequest request, HttpServletResponse response, int dispatch )
            throws IOException, ServletException
        {
            response.addHeader( "WWW-Authenticate", "NTLM" );
            response.setStatus( 401 );

            ( (Request) request ).setHandled( true );
        }
    }

    private static class AuthorizingProxyHandler
        extends TestHeaderHandler
    {
        @Override
        public void handle( String target, HttpServletRequest request, HttpServletResponse response, int dispatch )
            throws IOException, ServletException
        {
            if ( request.getHeader( "Proxy-Authorization" ) == null )
            {
                response.setStatus( 407 );
                response.addHeader( "Proxy-Authenticate", "Basic realm=\"Squid proxy-caching web server\"" );

                ( (Request) request ).setHandled( true );
                return;
            }
            super.handle( target, request, response, dispatch );
        }
    }

    private static class AuthorizingSecurityHandler
        extends SecurityHandler
    {
        public AuthorizingSecurityHandler()
        {
            Constraint constraint = new Constraint();
            constraint.setName( Constraint.__BASIC_AUTH );
            constraint.setRoles( new String[] { "admin" } );
            constraint.setAuthenticate( true );

            ConstraintMapping cm = new ConstraintMapping();
            cm.setConstraint( constraint );
            cm.setPathSpec( "/*" );

            HashUserRealm hashUserRealm = new HashUserRealm( "MyRealm" );
            hashUserRealm.put( "user", "secret" );
            hashUserRealm.addUserToRole( "user", "admin" );

            setUserRealm( hashUserRealm );
            setConstraintMappings( new ConstraintMapping[] { cm } );
        }
    }
}
