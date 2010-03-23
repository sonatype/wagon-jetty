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
import org.apache.maven.wagon.authentication.AuthenticationException;
import org.apache.maven.wagon.authentication.AuthenticationInfo;
import org.apache.maven.wagon.authorization.AuthorizationException;
import org.apache.maven.wagon.observers.ChecksumObserver;
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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.zip.GZIPOutputStream;

import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public abstract class HttpWagonTestCase
    extends StreamingWagonTestCase
{
    protected Server server;

    protected Connector[] connectors;

    protected Handler[] handlers;

    protected Context[] contexts;

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
        else if ( getProtocol().equalsIgnoreCase( "http" ) )
        {
            srv.addConnector( newHttpConnector() );
        }
        else
        {
            srv.addConnector( newHttpsConnector() );
        }
    }

    protected Connector newHttpConnector()
    {
        SelectChannelConnector connector = new SelectChannelConnector();
        return connector;
    }

    protected Connector newHttpsConnector()
    {
        return newHttpsConnector(false);
    }

    protected Connector newHttpsConnector(boolean needClientAuth)
    {
        SslSocketConnector connector = new SslSocketConnector();
        connector.setPort( 0 );
        connector.setKeystore( getTestFile( "src/test/resources/ssl/keystore" ).getAbsolutePath() );
        connector.setPassword( "storepwd" );
        connector.setKeyPassword( "keypwd" );
        connector.setTruststore( getTestFile( "src/test/resources/ssl/client-store" ).getAbsolutePath() );
        connector.setTrustPassword( "client-pwd" );
        connector.setNeedClientAuth( needClientAuth );
        return connector;
    }

    protected void addHandlers( final Server srv )
    {
        if ( handlers == null )
        {
            srv.addHandler( new RequestValidatorHandler() );
            PutHandler putHandler = new PutHandler( getRepositoryPath() );
            srv.addHandler( putHandler );
        }
        else
        {
            Handler[] h = new Handler[handlers.length + 1];
            System.arraycopy( handlers, 0, h, 1, handlers.length );
            h[0] = new RequestValidatorHandler();
            srv.setHandlers( h );
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

        testRepository = new Repository( "test", getTestRepositoryUrl() );
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
        // not supported
    }

    @Override
    public void testWagonGetFileListWhenDirectoryDoesNotExist()
        throws Exception
    {
        // not supported
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

    public void testGetFileThatIsBiggerThanMaxHeap()
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        long bytes = (long) ( Runtime.getRuntime().maxMemory() * 1.1 );

        handlers = new Handler[] { new HugeDataHandler( bytes ) };

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        File hugeFile = File.createTempFile( "wagon-test-" + getName(), ".tmp" );
        hugeFile.deleteOnExit();

        try
        {
            wagon.get( "huge.txt", hugeFile );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }

        assertTrue( hugeFile.isFile() );
        assertEquals( bytes, hugeFile.length() );
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

            assertEquals( "Basic dXNlcjpzZWNyZXQ=", handler.headers.get( "Proxy-Authorization" ) );
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
        FileUtils.fileWrite( srcFile.getAbsolutePath(), "UTF-8", "put top secret" );

        File dstFile = new File( getRepositoryPath() + "/secured", resName );
        dstFile.mkdirs();
        dstFile.delete();
        assertFalse( dstFile.exists() );

        StreamingWagon wagon = (StreamingWagon) getWagon();

        ChecksumObserver checksumObserver = new ChecksumObserver( "SHA-1" );
        wagon.addTransferListener( checksumObserver );

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ), authInfo );

        try
        {
            wagon.put( srcFile, "secured/" + resName );

            assertEquals( "put top secret", FileUtils.fileRead( dstFile.getAbsolutePath(), "UTF-8" ) );

            assertEquals( "8b4f978eeec389ebed2c8b0acd8e107efff29be5", checksumObserver.getActualChecksum() );
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

    public void testPutFileThatIsBiggerThanMaxHeap()
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        long bytes = (long) ( Runtime.getRuntime().maxMemory() * 1.1 );

        handlers = new Handler[] { new PutHandler( getRepositoryPath() ) };

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        File hugeFile = File.createTempFile( "wagon-test-" + getName(), ".tmp" );
        hugeFile.deleteOnExit();
        FileOutputStream fos = new FileOutputStream( hugeFile );
        IOUtil.copy( new HugeInputStream( bytes ), fos );
        fos.close();
        assertEquals( bytes, hugeFile.length() );

        try
        {
            wagon.put( hugeFile, "huge.txt" );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }

        File remoteFile = new File( getRepositoryPath(), "huge.txt" );
        assertTrue( remoteFile.isFile() );
        assertEquals( hugeFile.length(), remoteFile.length() );
    }

    public void testGetUnknownIP()
        throws Exception
    {
        runTestGetUnknown( "http://244.0.0.0/" );
    }

    public void testGetUnknownHost()
        throws Exception
    {
        runTestGetUnknown( "http://null.apache.org/" );
    }

    private void runTestGetUnknown( String url )
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        StreamingWagon wagon = (StreamingWagon) getWagon();
        wagon.setTimeout( 5000 );
        try

        {
            wagon.connect( new Repository( "id", url ) );

            wagon.getToStream( "resource", new StringOutputStream() );

            fail();
        }
        catch ( TransferFailedException ex )
        {
            assertTrue( true );
        }
    }

    public void testPutUnknownIP()
        throws Exception
    {
        runTestPutUnknown( "http://244.0.0.0/" );
    }

    public void testPutUnknownHost()
        throws Exception
    {
        runTestPutUnknown( "http://null.apache.org/" );
    }

    private void runTestPutUnknown( String url )
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        String resName = "put-res.txt";
        File srcFile = new File( getOutputPath(), resName );
        FileUtils.fileWrite( srcFile.getAbsolutePath(), "test put" );

        StreamingWagon wagon = (StreamingWagon) getWagon();
        wagon.setTimeout( 5000 );

        try
        {
            wagon.connect( new Repository( "id", url ) );

            wagon.put( srcFile, resName );

            fail();
        }
        catch ( TransferFailedException ex )
        {
            assertTrue( true );

            srcFile.delete();
        }
    }

    public void testHighLatencyGet()
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        Handler handler = new LatencyHandler( 500 );
        handlers = new Handler[] { handler };
        contexts = new Context[] {};

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        StreamingWagon wagon = (StreamingWagon) getWagon();

        // NOTE: 500 < 2000 < 5000, i.e the connection idles for only 500 ms and the overall transfer takes 5000 ms
        wagon.setTimeout( 2000 );

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        StringOutputStream out = new StringOutputStream();
        try
        {
            wagon.getToStream( "large.txt", out );

            assertEquals( out.toString().length(), 10240 );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    public void testInfiniteLatencyGet()
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        Handler handler = new LatencyHandler( -1 );
        handlers = new Handler[] { handler };
        contexts = new Context[] {};

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.setTimeout( 2000 );

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        StringOutputStream out = new StringOutputStream();
        try
        {
            wagon.getToStream( "large.txt", out );

            fail( "Should have failed to transfer due to transaction timeout." );
        }
        catch ( TransferFailedException e )
        {
            assertTrue( true );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    public void testGetRedirectOncePermanent()
        throws Exception
    {
        runTestRedirectSuccess( HttpServletResponse.SC_MOVED_PERMANENTLY, "/moved.txt", "/base.txt", 1, false );
    }

    public void testGetRedirectOnceTemporary()
        throws Exception
    {
        runTestRedirectSuccess( HttpServletResponse.SC_MOVED_TEMPORARILY, "/moved.txt", "/base.txt", 1, false );
    }

    public void testGetRedirectSixPermanent()
        throws Exception
    {
        runTestRedirectSuccess( HttpServletResponse.SC_MOVED_PERMANENTLY, "/moved.txt", "/base.txt", 6, false );
    }

    public void testGetRedirectSixTemporary()
        throws Exception
    {
        runTestRedirectSuccess( HttpServletResponse.SC_MOVED_TEMPORARILY, "/moved.txt", "/base.txt", 6, false );
    }

    public void testGetRedirectRelativeLocation()
        throws Exception
    {
        runTestRedirectSuccess( HttpServletResponse.SC_MOVED_PERMANENTLY, "/moved.txt", "/base.txt", 1, true );
    }

    private void runTestRedirectSuccess( int code, String currUrl, String origUrl, int maxRedirects, boolean relativeLocation )
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        Handler handler = new RedirectHandler( code, currUrl, origUrl, maxRedirects, relativeLocation );
        handlers = new Handler[] { handler };
        contexts = new Context[] {};

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        StringOutputStream out = new StringOutputStream();
        try
        {
            wagon.getToStream( currUrl, out );

            assertEquals( out.toString().length(), 1024 );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    public void testGetRedirectLimitPermanent()
        throws Exception
    {
        runTestRedirectFail( HttpServletResponse.SC_MOVED_PERMANENTLY, "/moved.txt", "/base.txt", -1 );
    }

    public void testGetRedirectLimitTemporary()
        throws Exception
    {
        runTestRedirectFail( HttpServletResponse.SC_MOVED_TEMPORARILY, "/moved.txt", "/base.txt", -1 );
    }

    private void runTestRedirectFail( int code, String currUrl, String origUrl, int maxRedirects )
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        Handler handler = new RedirectHandler( code, currUrl, origUrl, maxRedirects, false );
        handlers = new Handler[] { handler };
        contexts = new Context[] {};

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        StringOutputStream out = new StringOutputStream();
        try
        {
            wagon.getToStream( currUrl, out );
            fail();
        }
        catch ( TransferFailedException ex )
        {
            assertTrue( true );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    public void testGracefulFailureUnderMultithreadedMisuse()
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        Handler handler = new LatencyHandler( 500 );
        handlers = new Handler[] { handler };
        contexts = new Context[] {};

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        final StreamingWagon wagon = (StreamingWagon) getWagon();

        wagon.connect( new Repository( "id", getTestRepositoryUrl() ) );

        new Thread( new Runnable()
        {

            public void run()
            {
                try
                {
                    Thread.sleep( 1000 );
                    // closing the wagon from another thread must not hang the main thread
                    wagon.disconnect();
                }
                catch ( Exception e )
                {
                    e.printStackTrace();
                }
            }

        }, "wagon-killer" ).start();

        try
        {
            wagon.getToStream( "large.txt", new ByteArrayOutputStream() );
        }
        catch ( TransferFailedException ex )
        {
            assertTrue( true );
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    static class StatusHandler
        extends AbstractHandler
    {
        private int status;

        public StatusHandler()
        {
            this( 0 );
        }

        public StatusHandler( int status )
        {
            this.status = status;
        }

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

    private static class LatencyHandler
        extends AbstractHandler
    {
        private long delay;

        public LatencyHandler( long delay )
        {
            this.delay = delay;
        }

        public void handle( String target, HttpServletRequest request, HttpServletResponse response, int dispatch )
            throws IOException, ServletException
        {
            if ( ( (Request) request ).isHandled() )
            {
                return;
            }

            if ( delay < 0 )
            {
                System.out.println( "Starting infinite wait." );
                synchronized ( this )
                {
                    try
                    {
                        wait();
                    }
                    catch ( InterruptedException e )
                    {
                    }
                }

                return;
            }

            Random randGen = new Random();

            int buffSize = 1024;
            byte[] buff = new byte[buffSize];
            randGen.nextBytes( buff );

            for ( int idx = 0; idx < buffSize; idx++ )
            {
                buff[idx] = (byte) ( buff[idx] & 0x6F + (int) ' ' );
            }

            OutputStream out = response.getOutputStream();
            for ( int cnt = 0; cnt < 10; cnt++ )
            {
                try
                {
                    Thread.sleep( delay );
                }
                catch ( InterruptedException ex )
                {
                    // consume exception
                }

                out.write( buff );
                out.flush();
            }

            ( (Request) request ).setHandled( true );
        }
    }

    private static class RedirectHandler
        extends AbstractHandler
    {
        private final String origUrl;

        private final int code;

        private final int maxRedirects;

        private int redirectCount = 0;

        private final String currUrl;

        private final boolean relativeLocation;

        public RedirectHandler( final int code, final String currUrl, final String origUrl, final int maxRedirects, boolean relativeLocation )
        {
            this.code = code;
            this.currUrl = currUrl;
            this.origUrl = origUrl;
            this.maxRedirects = maxRedirects;
            this.relativeLocation = relativeLocation;
        }

        public void handle( String target, HttpServletRequest request, HttpServletResponse response, int dispatch )
            throws IOException, ServletException
        {
            if ( ( (Request) request ).isHandled() )
            {
                return;
            }

            if ( request.getRequestURI().equals( currUrl ) )
            {
                redirectCount++;

                String location;
                if ( maxRedirects < 0 || redirectCount < maxRedirects )
                {
                    location = currUrl;
                }
                else
                {
                    location = origUrl;
                }

                if ( !relativeLocation && location.startsWith( "/" ) )
                {
                    String base = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort();
                    location = base + location;
                }

                response.setStatus( code );
                response.setHeader( "Location", location );
                ( (Request) request ).setHandled( true );
            }
            else if ( request.getRequestURI().equals( origUrl ) )
            {
                Random randGen = new Random();

                int buffSize = 1024;
                byte[] buff = new byte[buffSize];
                randGen.nextBytes( buff );

                for ( int idx = 0; idx < buffSize; idx++ )
                {
                    buff[idx] = (byte) ( buff[idx] & 0x2F + (int) ' ' );
                }

                OutputStream out = response.getOutputStream();
                out.write( buff );

                ( (Request) request ).setHandled( true );
            }
        }
    }

    static class HugeDataHandler
        extends AbstractHandler
    {

        private long size;

        public HugeDataHandler( long size )
        {
            this.size = size;
        }

        public void handle( String target, HttpServletRequest request, HttpServletResponse response, int dispatch )
            throws IOException
        {
            if ( "GET".equals( request.getMethod() ) )
            {
                OutputStream os = response.getOutputStream();

                IOUtil.copy( new HugeInputStream( size ), os );
                os.close();

                response.setStatus( 200 );
                ( (Request) request ).setHandled( true );
            }
        }

    }

    static class RequestValidatorHandler
        extends AbstractHandler
    {

        public void handle( String target, HttpServletRequest request, HttpServletResponse response, int dispatch )
        {
            if ( "GET".equals( request.getMethod() ) || "HEAD".equals( request.getMethod() ) )
            {
                if ( request.getHeader( "Content-Length" ) != null )
                {
                    /*
                     * While the HTTP spec does not clearly prohibit a request body for a GET/HEAD, the feedback we got
                     * on MNGECLIPSE-1975 indicates that at least some (proxy) servers out there choke if a body is
                     * sent.
                     */
                    /* https://bugs.eclipse.org/bugs/show_bug.cgi?id=306840
                    response.setStatus( HttpServletResponse.SC_BAD_REQUEST );
                    ( (Request) request ).setHandled( true );
                    //*/
                }
            }
        }

    }

}
