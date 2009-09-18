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

import org.apache.maven.wagon.ConnectionException;
import org.apache.maven.wagon.ResourceDoesNotExistException;
import org.apache.maven.wagon.StreamingWagon;
import org.apache.maven.wagon.TransferFailedException;
import org.apache.maven.wagon.Wagon;
import org.apache.maven.wagon.authentication.AuthenticationException;
import org.apache.maven.wagon.authentication.AuthenticationInfo;
import org.apache.maven.wagon.authorization.AuthorizationException;
import org.apache.maven.wagon.proxy.ProxyInfo;
import org.apache.maven.wagon.repository.Repository;
import org.apache.maven.wagon.resource.Resource;
import org.codehaus.plexus.util.FileUtils;
import org.codehaus.plexus.util.IOUtil;
import org.codehaus.plexus.util.StringOutputStream;
import org.mortbay.jetty.Connector;
import org.mortbay.jetty.Handler;
import org.mortbay.jetty.HttpConnection;
import org.mortbay.jetty.Request;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.handler.AbstractHandler;
import org.mortbay.jetty.nio.SelectChannelConnector;
import org.mortbay.jetty.security.Constraint;
import org.mortbay.jetty.security.ConstraintMapping;
import org.mortbay.jetty.security.HashUserRealm;
import org.mortbay.jetty.security.SecurityHandler;
import org.mortbay.jetty.security.SslSocketConnector;
import org.mortbay.jetty.servlet.Context;
import org.mortbay.jetty.servlet.DefaultServlet;
import org.mortbay.jetty.servlet.ServletHolder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.zip.GZIPOutputStream;

import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public abstract class HttpWagonTestCase
    extends StreamingWagonTestCase
{
    private Server server;

    private Connector[] connectors;

    private Handler[] handlers;

    private Context[] contexts;

    @Override
    protected void setupTestServer()
        throws Exception
    {
        stopTestServer();

        File repositoryDirectory = getRepositoryDirectory();
        FileUtils.deleteDirectory( repositoryDirectory );
        repositoryDirectory.mkdirs();

        server = new Server( 0 );

        addConnectors( server );
        addHandlers( server );
        addContexts( server );

        server.start();
    }

    @Override
    protected void stopTestServer()
        throws Exception
    {
        if ( server != null )
        {
            server.stop();
            server = null;
        }
    }

    protected void addConnectors( final Server srv )
    {
        if ( connectors != null )
        {
            srv.setConnectors( connectors );
            connectors = null;
        }
        if ( getProtocol().equalsIgnoreCase( "http" ) )
        {
            SelectChannelConnector connector = new SelectChannelConnector();
            server.addConnector( connector );
        }
        else
        {
            SslSocketConnector connector = new SslSocketConnector();
            String keystore = getTestFile( "src/test/resources/ssl/keystore" ).getAbsolutePath();
            connector.setPort( 0 );
            connector.setKeystore( keystore );
            connector.setPassword( "storepwd" );
            connector.setKeyPassword( "keypwd" );
            server.addConnector( connector );
        }
    }

    protected void addHandlers( final Server srv )
    {
        if ( handlers == null )
        {
            PutHandler putHandler = new PutHandler( getRepositoryPath() );
            srv.addHandler( putHandler );
        }
        else
        {
            srv.setHandlers( handlers );
            handlers = null;
        }
    }

    protected void addContexts( final Server srv )
        throws IOException
    {
        if ( contexts == null )
        {
            Context root = new Context( srv, "/", Context.SESSIONS );
            root.setResourceBase( getRepositoryPath() );
            ServletHolder servletHolder = new ServletHolder( new DefaultServlet() );
            servletHolder.setInitParameter( "gzip", "true" );
            root.addServlet( servletHolder, "/*" );
        }
        else
        {
            for ( Context ctx : contexts )
            {
                srv.addHandler( ctx );
            }
            contexts = null;
        }
    }

    @Override
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

    @Override
    protected String getTestRepositoryUrl()
    {
        return getProtocol() + "://localhost:" + getLocalPort();
    }

    protected int getLocalPort()
    {
        Connector[] cons = server.getConnectors();
        return cons[cons.length - 1].getLocalPort();
    }

    @Override
    protected void setupWagonTestingFixtures()
        throws Exception
    {
    }

    @Override
    protected void tearDownWagonTestingFixtures()
        throws Exception
    {
    }

    @Override
    public void testWagonGetFileList()
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        String dirName = "file-list";
        File f = new File( getRepositoryPath(), dirName );
        f.mkdirs();

        String filenames[] =
            new String[] { "test-resource.txt", "test-resource.pom", "test-resource b.txt", "more-resources.dat",
                ".index.txt" };

        for ( int i = 0; i < filenames.length; i++ )
        {
            putFile( dirName + "/" + filenames[i], dirName + "/" + filenames[i], filenames[i] + "\n" );
        }

        Wagon wagon = getWagon();

        wagon.connect( testRepository, getAuthInfo() );

        List list = wagon.getFileList( dirName );
        assertNotNull( "file list should not be null.", list );
        assertTrue( "file list should contain more items (actually contains '" + list + "').",
                    list.size() >= filenames.length );

        for ( int i = 0; i < filenames.length; i++ )
        {
            assertTrue( "Filename '" + filenames[i] + "' should be in list.", list.contains( filenames[i] ) );
        }

        // WAGON-250
        list = wagon.getFileList( "" );
        assertNotNull( "file list should not be null.", list );
        assertTrue( "file list should contain items (actually contains '" + list + "').", !list.isEmpty() );
        assertTrue( list.contains( "file-list/" ) );
        assertFalse( list.contains( "file-list" ) );
        assertFalse( list.contains( "." ) );
        assertFalse( list.contains( ".." ) );
        assertFalse( list.contains( "./" ) );
        assertFalse( list.contains( "../" ) );

        wagon.disconnect();

        tearDownWagonTestingFixtures();

        stopTestServer();
    }

    public void testHttpHeaders()
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        Properties properties = new Properties();
        properties.setProperty( "User-Agent", "Maven-Wagon/1.0" );

        StreamingWagon wagon = (StreamingWagon) getWagon();
        setHttpHeaders( wagon, properties );

        TestHeaderHandler handler = new TestHeaderHandler();
        handlers = new Handler[] { handler };
        contexts = new Context[] {};

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        wagon.getToStream( "resource", new StringOutputStream() );

        wagon.disconnect();

        tearDownWagonTestingFixtures();

        stopTestServer();

        assertEquals( "Maven-Wagon/1.0", handler.headers.get( "User-Agent" ) );
    }

    protected abstract void setHttpHeaders( StreamingWagon wagon, Properties properties );

    public void testGetForbidden()
        throws Exception
    {
        try
        {
            runTestGet( HttpServletResponse.SC_FORBIDDEN );
            fail();
        }
        catch ( AuthorizationException e )
        {
            assertTrue( true );
        }
    }

    public void testGet404()
        throws Exception
    {
        try
        {
            runTestGet( HttpServletResponse.SC_NOT_FOUND );
            fail();
        }
        catch ( ResourceDoesNotExistException e )
        {
            assertTrue( true );
        }
    }

    public void testGet500()
        throws Exception
    {
        try
        {
            runTestGet( HttpServletResponse.SC_INTERNAL_SERVER_ERROR );
            fail();
        }
        catch ( TransferFailedException e )
        {

        }
    }

    private void runTestGet( final int status )
        throws Exception, ConnectionException, AuthenticationException, TransferFailedException,
        ResourceDoesNotExistException, AuthorizationException
    {
        alert( "\n\nRunning test: " + getName() );

        StreamingWagon wagon = (StreamingWagon) getWagon();

        StatusHandler handler = new StatusHandler();
        handler.setStatusToReturn( status );
        handlers = new Handler[] { handler };
        contexts = new Context[] {};

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        try
        {
            wagon.getToStream( "resource", new StringOutputStream() );
            fail();
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    public void testResourceExistsForbidden()
        throws Exception
    {
        try
        {
            runTestResourceExists( HttpServletResponse.SC_FORBIDDEN );
            fail();
        }
        catch ( AuthorizationException e )
        {
            assertTrue( true );
        }
    }

    public void testResourceExists404()
        throws Exception
    {
        try
        {
            assertFalse( runTestResourceExists( HttpServletResponse.SC_NOT_FOUND ) );
        }
        catch ( ResourceDoesNotExistException e )
        {
            assertTrue( true );
        }
    }

    public void testResourceExists500()
        throws Exception
    {
        try
        {
            runTestResourceExists( HttpServletResponse.SC_INTERNAL_SERVER_ERROR );
            fail();
        }
        catch ( TransferFailedException e )
        {
            assertTrue( true );
        }
    }

    private boolean runTestResourceExists( final int status )
        throws Exception, ConnectionException, AuthenticationException, TransferFailedException,
        ResourceDoesNotExistException, AuthorizationException
    {
        alert( "\n\nRunning test: " + getName() );

        StreamingWagon wagon = (StreamingWagon) getWagon();

        StatusHandler handler = new StatusHandler();
        handler.setStatusToReturn( status );
        handlers = new Handler[] { handler };
        contexts = new Context[] {};

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        try
        {
            return wagon.resourceExists( "resource" );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    @Override
    protected long getExpectedLastModifiedOnGet( final Repository repository, final Resource resource )
    {
        File file = new File( getRepositoryPath(), resource.getName() );
        return ( file.lastModified() / 1000 ) * 1000;
    }

    public void testGzipGet()
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        StreamingWagon wagon = (StreamingWagon) getWagon();

        File srcFile = new File( getRepositoryPath() + "/gzip" );
        // srcFile.deleteOnExit();

        String resName = "gzip-res.txt";
        String sourceContent = writeTestFileGzip( srcFile, resName );

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        StringOutputStream out = new StringOutputStream();
        try
        {
            wagon.getToStream( "gzip/" + resName, out );

            assertEquals( sourceContent, out.toString() );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    private String writeTestFileGzip( final File parent, final String child )
        throws IOException
    {
        File file = new File( parent, child );
        file.getParentFile().mkdirs();
        // file.deleteOnExit();
        OutputStream out = new FileOutputStream( file );
        out.write( child.getBytes() );
        out.close();

        file = new File( parent, child + ".gz" );
        // file.deleteOnExit();
        out = new FileOutputStream( file );
        out = new GZIPOutputStream( out );
        // write out different data than non-gz file, so we can
        // assert the gz version was returned
        String content = file.getAbsolutePath();
        out.write( content.getBytes() );
        out.close();
        return content;
    }

    public void testProxiedRequest()
        throws Exception
    {
        if ( getProtocol().equals( "http" ) )
        {
            ProxyInfo proxyInfo = createProxyInfo();
            TestHeaderHandler handler = new TestHeaderHandler();

            runTestProxiedRequest( proxyInfo, handler );
        }
    }

    public void testProxiedRequestWithAuthentication()
        throws Exception
    {
        if ( getProtocol().equals( "http" ) )
        {
            ProxyInfo proxyInfo = createProxyInfo();
            proxyInfo.setUserName( "user" );
            proxyInfo.setPassword( "secret" );
            TestHeaderHandler handler = new AuthorizingProxyHandler();

            runTestProxiedRequest( proxyInfo, handler );

            assertTrue( handler.headers.containsKey( "Proxy-Authorization" ) );
        }
    }

    private void runTestProxiedRequest( final ProxyInfo proxyInfo, final TestHeaderHandler handler )
        throws Exception, IOException, ConnectionException, AuthenticationException, ResourceDoesNotExistException,
        TransferFailedException, AuthorizationException
    {
        alert( "\n\nRunning test: " + getName() );

        handlers = new Handler[] { handler };

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        proxyInfo.setPort( getLocalPort() );

        File srcFile = new File( getRepositoryPath() + "/proxy" );
        srcFile.mkdirs();
        srcFile.deleteOnExit();

        String resName = "proxy-res.txt";
        FileUtils.fileWrite( srcFile.getAbsolutePath() + "/" + resName, "test proxy" );

        File destFile = new File( getOutputPath(), getName() + ".txt" );
        destFile.deleteOnExit();

        Properties properties = new Properties();
        properties.setProperty( "Proxy-Connection", "close" );

        StreamingWagon wagon = (StreamingWagon) getWagon();
        setHttpHeaders( wagon, properties );

        wagon.connect( new Repository( "id", "http://www.example.com/" ), proxyInfo );

        try
        {
            wagon.get( "proxy/" + resName, destFile );

            assertTrue( handler.headers.containsKey( "Proxy-Connection" ) );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    private ProxyInfo createProxyInfo()
    {
        ProxyInfo proxyInfo = new ProxyInfo();
        proxyInfo.setHost( "localhost" );
        proxyInfo.setNonProxyHosts( null );
        proxyInfo.setType( "http" );
        return proxyInfo;
    }

    public void testSecuredGetUnauthorized()
        throws Exception
    {
        try
        {
            runTestSecuredGet( null );
            fail();
        }
        catch ( AuthorizationException e )
        {
            assertTrue( true );
        }
    }

    public void testSecuredGetWrongPassword()
        throws Exception
    {
        try
        {
            AuthenticationInfo authInfo = new AuthenticationInfo();
            authInfo.setUserName( "user" );
            authInfo.setPassword( "admin" );
            runTestSecuredGet( authInfo );
            fail();
        }
        catch ( AuthorizationException e )
        {
            assertTrue( true );
        }
    }

    public void testSecuredGet()
        throws Exception
    {
        AuthenticationInfo authInfo = new AuthenticationInfo();
        authInfo.setUserName( "user" );
        authInfo.setPassword( "secret" );
        runTestSecuredGet( authInfo );
    }

    public void runTestSecuredGet( final AuthenticationInfo authInfo )
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        Context context = createSecuredContext();
        handlers = new Handler[] { context };
        contexts = new Context[] {};

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        File srcFile = new File( getRepositoryPath() + "/secured" );
        srcFile.mkdirs();
        srcFile.deleteOnExit();

        String resName = "secured-res.txt";
        FileUtils.fileWrite( srcFile.getAbsolutePath() + "/" + resName, "top secret" );

        StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ), authInfo );

        StringOutputStream out = new StringOutputStream();
        try
        {
            wagon.getToStream( "secured/" + resName, out );

            assertEquals( "top secret", out.toString() );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    public Context createSecuredContext()
    {
        Context root = new Context( Context.SESSIONS );
        root.setContextPath( "/" );
        root.addHandler( new AuthorizingSecurityHandler() );
        root.setResourceBase( getRepositoryPath() );
        ServletHolder servletHolder = new ServletHolder( new DefaultServlet() );
        root.addServlet( servletHolder, "/*" );

        return root;
    }

    public void testSecuredResourceExistsUnauthorized()
        throws Exception
    {
        try
        {
            runTestSecuredResourceExists( null );
            fail();
        }
        catch ( AuthorizationException e )
        {
            assertTrue( true );
        }
    }

    public void testSecuredResourceExistsWrongPassword()
        throws Exception
    {
        try
        {
            AuthenticationInfo authInfo = new AuthenticationInfo();
            authInfo.setUserName( "user" );
            authInfo.setPassword( "admin" );
            runTestSecuredResourceExists( authInfo );
        }
        catch ( AuthorizationException e )
        {
            assertTrue( true );
        }
    }

    public void testSecuredResourceExists()
        throws Exception
    {
        AuthenticationInfo authInfo = new AuthenticationInfo();
        authInfo.setUserName( "user" );
        authInfo.setPassword( "secret" );
        runTestSecuredResourceExists( authInfo );
    }

    public void runTestSecuredResourceExists( final AuthenticationInfo authInfo )
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        Context context = createSecuredContext();
        handlers = new Handler[] { context };

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        File srcFile = new File( getRepositoryPath() + "/secured" );
        srcFile.mkdirs();
        srcFile.deleteOnExit();

        String resName = "secured-res.txt";
        FileUtils.fileWrite( srcFile.getAbsolutePath() + "/" + resName, "top secret" );

        StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ), authInfo );

        try
        {
            assertTrue( wagon.resourceExists( "secured/" + resName ) );

            assertFalse( wagon.resourceExists( "secured/missing-" + resName ) );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    public void testPutForbidden()
        throws Exception
    {
        try
        {
            runTestPutFailure( HttpServletResponse.SC_FORBIDDEN );
            fail();
        }
        catch ( AuthorizationException e )
        {
            assertTrue( true );
        }
    }

    public void testPut404()
        throws Exception
    {
        try
        {
            runTestPutFailure( HttpServletResponse.SC_NOT_FOUND );
            fail();
        }
        catch ( ResourceDoesNotExistException e )
        {
            assertTrue( true );
        }
    }

    public void testPut500()
        throws Exception
    {
        try
        {
            runTestPutFailure( HttpServletResponse.SC_INTERNAL_SERVER_ERROR );
            fail();
        }
        catch ( TransferFailedException e )
        {
            assertTrue( true );
        }
    }

    private void runTestPutFailure( final int status )
        throws Exception, ConnectionException, AuthenticationException, TransferFailedException,
        ResourceDoesNotExistException, AuthorizationException
    {
        alert( "\n\nRunning test: " + getName() );

        StatusHandler handler = new StatusHandler();
        handler.setStatusToReturn( status );
        handlers = new Handler[] { handler };

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        String resName = "put-res.txt";
        File srcFile = new File( getOutputPath(), resName );
        FileUtils.fileWrite( srcFile.getAbsolutePath(), "test put" );

        StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        try
        {
            wagon.put( srcFile, resName );
            fail();
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();

            srcFile.delete();
        }
    }

    public void testSecuredPutUnauthorized()
        throws Exception
    {
        try
        {
            runTestSecuredPut( null );
            fail();
        }
        catch ( AuthorizationException e )
        {
            assertTrue( true );
        }
    }

    public void testSecuredPutWrongPassword()
        throws Exception
    {
        try
        {
            AuthenticationInfo authInfo = new AuthenticationInfo();
            authInfo.setUserName( "user" );
            authInfo.setPassword( "admin" );
            runTestSecuredPut( authInfo );
            fail();
        }
        catch ( AuthorizationException e )
        {
            assertTrue( true );
        }
    }

    public void testSecuredPut()
        throws Exception
    {
        AuthenticationInfo authInfo = new AuthenticationInfo();
        authInfo.setUserName( "user" );
        authInfo.setPassword( "secret" );
        runTestSecuredPut( authInfo );
    }

    public void runTestSecuredPut( final AuthenticationInfo authInfo )
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        AuthorizingSecurityHandler shandler = new AuthorizingSecurityHandler();
        PutHandler handler = new PutHandler( getRepositoryPath() );
        shandler.addHandler( handler ); // must nest the put handler behind the authorization handler
        handlers = new Handler[] { shandler };
        contexts = new Context[] {};

        // must setup server after handlers are setup
        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        String resName = "secured-put-res.txt";
        File srcFile = new File( getOutputPath(), resName );
        FileUtils.fileWrite( srcFile.getAbsolutePath(), "put top secret" );

        File dstFile = new File( getRepositoryPath() + "/secured", resName );
        dstFile.mkdirs();
        dstFile.delete();
        assertFalse( dstFile.exists() );

        StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ), authInfo );

        try
        {
            wagon.put( srcFile, "secured/" + resName );

            assertEquals( "put top secret", FileUtils.fileRead( dstFile.getAbsolutePath() ) );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();

            // srcFile.delete();
        }
    }

    public void testPut()
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        PutHandler handler = new PutHandler( getRepositoryPath() );
        handlers = new Handler[] { handler };
        contexts = new Context[] {};

        // must setup server after handlers are setup
        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        String resName = "put-res.txt";
        File srcFile = new File( getOutputPath(), resName );
        FileUtils.fileWrite( srcFile.getAbsolutePath(), "test put" );

        File dstFile = new File( getRepositoryPath() + "/put", resName );
        dstFile.mkdirs();
        dstFile.delete();
        assertFalse( dstFile.exists() );

        StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        try
        {
            wagon.put( srcFile, "put/" + resName );

            assertEquals( "test put", FileUtils.fileRead( dstFile.getAbsolutePath() ) );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();

            srcFile.delete();
        }
    }

    static class StatusHandler
        extends AbstractHandler
    {
        private int status;

        public void setStatusToReturn( final int status )
        {
            this.status = status;
        }

        public void handle( final String target, final HttpServletRequest request, final HttpServletResponse response,
                            final int dispatch )
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

        public PutHandler( final String repositoryPath )
        {
            this.resourcePath = repositoryPath;
        }

        public void handle( final String target, final HttpServletRequest request, final HttpServletResponse response,
                            final int dispatch )
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
        public void handle( final String target, final HttpServletRequest request, final HttpServletResponse response,
                            final int dispatch )
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

    private static class AuthorizingProxyHandler
        extends TestHeaderHandler
    {
        public void handle( final String target, final HttpServletRequest request, final HttpServletResponse response,
                            final int dispatch )
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
