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
import org.apache.maven.wagon.FileTestUtils;
import org.apache.maven.wagon.ResourceDoesNotExistException;
import org.apache.maven.wagon.TransferFailedException;
import org.apache.maven.wagon.Wagon;
import org.apache.maven.wagon.authentication.AuthenticationException;
import org.apache.maven.wagon.authentication.AuthenticationInfo;
import org.apache.maven.wagon.authorization.AuthorizationException;
import org.apache.maven.wagon.events.TransferEvent;
import org.apache.maven.wagon.events.TransferListener;
import org.apache.maven.wagon.observers.ChecksumObserver;
import org.apache.maven.wagon.observers.Debug;
import org.apache.maven.wagon.repository.Repository;
import org.apache.maven.wagon.repository.RepositoryPermissions;
import org.apache.maven.wagon.resource.Resource;
import org.codehaus.plexus.PlexusTestCase;
import org.codehaus.plexus.util.FileUtils;
import org.easymock.AbstractMatcher;
import org.easymock.MockControl;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * @author <a href="mailto:jason@maven.org">Jason van Zyl</a>
 */
public abstract class WagonTestCase
    extends PlexusTestCase
{
    public static final class ProgressArgumentMatcher
        extends AbstractMatcher
    {
        private int size;

        @Override
        protected boolean argumentMatches( final Object expected, final Object actual )
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

    @Override
    protected void setUp()
        throws Exception
    {
        checksumObserver = new ChecksumObserver();

        mockTransferListenerControl = MockControl.createControl( TransferListener.class );
        mockTransferListener = (TransferListener) mockTransferListenerControl.getMock();

        super.setUp();
    }

    // ----------------------------------------------------------------------
    // Methods that should be provided by subclasses for proper testing
    // ----------------------------------------------------------------------

    protected abstract void setupTestServer()
        throws Exception;

    protected abstract void stopTestServer()
        throws Exception;

    /**
     * URL of the repository. For a complete test it should point to a non existing folder so we also check for the
     * creation of new folders in the remote site.
     * <p/>
     * return the URL of the repository as specified by Wagon syntax
     */
    protected abstract String getTestRepositoryUrl()
        throws IOException;

    /**
     * Protocol id of the Wagon to use, eg. <code>scp</code>, <code>ftp</code>
     * 
     * @return the protocol id
     */
    protected abstract String getProtocol();

    // ----------------------------------------------------------------------
    // 1. Create a local file repository which mimic a users local file
    // Repository.
    //
    // 2. Create a test repository for the type of wagon we are testing. So,
    // for example, for testing the file wagon we might have a test
    // repository url of file://${basedir}/target/file-repository.
    // ----------------------------------------------------------------------

    protected void setupRepositories()
        throws Exception
    {
        resource = "test-resource";

        // ----------------------------------------------------------------------
        // Create the test repository for the wagon we are testing.
        // ----------------------------------------------------------------------

        testRepository = new Repository();

        testRepository.setUrl( getTestRepositoryUrl() );

        testRepository.setPermissions( getPermissions() );

        // ----------------------------------------------------------------------
        // Create a test local repository.
        // ----------------------------------------------------------------------

        localRepositoryPath = FileTestUtils.createDir( "local-repository" ).getPath();

        localRepository = createFileRepository( "file://" + localRepositoryPath );

        message( "Local repository: " + localRepository );

        File f = new File( localRepositoryPath );

        if ( !f.exists() )
        {
            f.mkdirs();
        }
    }

    protected void customizeContext()
        throws Exception
    {
        getContainer().addContextValue( "test.repository", localRepositoryPath );
    }

    protected void setupWagonTestingFixtures()
        throws Exception
    {
    }

    protected void tearDownWagonTestingFixtures()
        throws Exception
    {
    }

    // ----------------------------------------------------------------------
    //
    // ----------------------------------------------------------------------

    protected AuthenticationInfo getAuthInfo()
    {
        return new AuthenticationInfo();
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

    protected void message( final String message )
    {
        System.out.println( message );
    }

    protected void alert( final String message )
    {
        System.err.println( message );
    }

    // ----------------------------------------------------------------------
    //
    // ----------------------------------------------------------------------

    public void testWagon()
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        fileRoundTripTesting();

        tearDownWagonTestingFixtures();

        stopTestServer();
    }

    public void testWagonGetIfNewerIsNewer()
        throws Exception
    {
        if ( supportsGetIfNewer() )
        {
            alert( "\n\nRunning test: " + getName() );

            setupTestServer();

            setupRepositories();

            setupWagonTestingFixtures();

            int expectedSize = putFile();

            getIfNewer( getExpectedLastModifiedOnGet( testRepository, new Resource( resource ) ) + 30000, false,
                        expectedSize );
        }
    }

    protected boolean supportsGetIfNewer()
    {
        return true;
    }

    public void testWagonGetIfNewerIsOlder()
        throws Exception
    {
        if ( supportsGetIfNewer() )
        {
            alert( "\n\nRunning test: " + getName() );

            setupTestServer();

            setupRepositories();

            setupWagonTestingFixtures();

            int expectedSize = putFile();

            getIfNewer( new SimpleDateFormat( "yyyy-MM-dd" ).parse( "2006-01-01" ).getTime(), true, expectedSize );
        }
    }

    public void testWagonGetIfNewerIsSame()
        throws Exception
    {
        if ( supportsGetIfNewer() )
        {
            alert( "\n\nRunning test: " + getName() );

            setupTestServer();

            setupRepositories();

            setupWagonTestingFixtures();

            int expectedSize = putFile();

            getIfNewer( getExpectedLastModifiedOnGet( testRepository, new Resource( resource ) ), false, expectedSize );
        }
    }

    private void getIfNewer( final long timestamp, final boolean expectedResult, final int expectedSize )
        throws Exception, NoSuchAlgorithmException, IOException, ConnectionException, AuthenticationException,
        TransferFailedException, ResourceDoesNotExistException, AuthorizationException
    {
        Wagon wagon = getWagon();

        ProgressArgumentMatcher progressArgumentMatcher = setupGetIfNewerTest( wagon, expectedResult, expectedSize );

        connectWagon( wagon );

        boolean result = wagon.getIfNewer( this.resource, destFile, timestamp );
        assertEquals( expectedResult, result );

        disconnectWagon( wagon );

        assertGetIfNewerTest( progressArgumentMatcher, expectedResult, expectedSize );

        tearDownWagonTestingFixtures();

        stopTestServer();
    }

    protected void assertGetIfNewerTest( final ProgressArgumentMatcher progressArgumentMatcher,
                                         final boolean expectedResult, final int expectedSize )
        throws IOException
    {
        if ( expectedResult == true )
        {
            verifyMock( progressArgumentMatcher, expectedSize );

            assertNotNull( "check checksum is not null", checksumObserver.getActualChecksum() );

            assertEquals( "compare checksums", "6b144b7285ffd6b0bc8300da162120b9", checksumObserver.getActualChecksum() );

            // Now compare the contents of the artifact that was placed in
            // the repository with the contents of the artifact that was
            // retrieved from the repository.

            String sourceContent = FileUtils.fileRead( sourceFile );
            String destContent = FileUtils.fileRead( destFile );
            assertEquals( sourceContent, destContent );
        }
        else
        {
            mockTransferListenerControl.verify();

            mockTransferListenerControl.reset();

            assertNull( "check checksum is null", checksumObserver.getActualChecksum() );

            assertFalse( destFile.exists() );
        }
    }

    protected ProgressArgumentMatcher setupGetIfNewerTest( final Wagon wagon, final boolean expectedResult,
                                                           final int expectedSize )
        throws NoSuchAlgorithmException, IOException
    {
        checksumObserver = new ChecksumObserver();

        destFile = getTestFile( getName() + ".txt" );
        destFile.delete();
        assertFalse( destFile.exists() );
        destFile.deleteOnExit();

        ProgressArgumentMatcher progressArgumentMatcher = null;
        if ( expectedResult == true )
        {
            progressArgumentMatcher = replaceMockForGet( wagon, expectedSize );
        }
        else
        {
            replaceMockForSkippedGetIfNewer( wagon, expectedSize );
        }
        return progressArgumentMatcher;
    }

    private void replaceMockForSkippedGetIfNewer( final Wagon wagon, final int expectedSize )
    {
        Resource resource = new Resource( this.resource );
        mockTransferListener.transferInitiated( createTransferEvent( wagon, resource, TransferEvent.TRANSFER_INITIATED,
                                                                     TransferEvent.REQUEST_GET, destFile ) );
        resource = new Resource( this.resource );
        resource.setContentLength( getExpectedContentLengthOnGet( expectedSize ) );
        resource.setLastModified( getExpectedLastModifiedOnGet( testRepository, resource ) );
        // TODO: transfer skipped event?
        // mockTransferListener.transferSkipped( createTransferEvent( wagon, resource, TransferEvent.TRANSFER_STARTED,
        // TransferEvent.REQUEST_GET, destFile ) );

        mockTransferListener.debug( null );
        mockTransferListenerControl.setMatcher( MockControl.ALWAYS_MATCHER );
        mockTransferListenerControl.setVoidCallable( MockControl.ZERO_OR_MORE );

        mockTransferListenerControl.replay();
    }

    public void testWagonPutDirectory()
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        Wagon wagon = getWagon();

        if ( wagon.supportsDirectoryCopy() )
        {
            sourceFile = new File( FileTestUtils.getTestOutputDir(), "directory-copy" );

            FileUtils.deleteDirectory( sourceFile );

            writeTestFile( "test-resource-1.txt" );
            writeTestFile( "a/test-resource-2.txt" );
            writeTestFile( "a/b/test-resource-3.txt" );
            writeTestFile( "c/test-resource-4.txt" );
            writeTestFile( "d/e/f/test-resource-5.txt" );

            wagon.connect( testRepository, getAuthInfo() );

            wagon.putDirectory( sourceFile, "directory-copy" );

            destFile = getTestFile( getName() + ".txt" );
            destFile.deleteOnExit();

            wagon.get( "directory-copy/test-resource-1.txt", destFile );
            wagon.get( "directory-copy/a/test-resource-2.txt", destFile );
            wagon.get( "directory-copy/a/b/test-resource-3.txt", destFile );
            wagon.get( "directory-copy/c/test-resource-4.txt", destFile );
            wagon.get( "directory-copy/d/e/f/test-resource-5.txt", destFile );

            wagon.disconnect();
        }

        tearDownWagonTestingFixtures();

        stopTestServer();
    }

    /**
     * Test for putting a directory with a destination that multiple directories deep, all of which haven't been
     * created.
     * 
     * @throws Exception
     * @since 1.0-beta-2
     */
    public void testWagonPutDirectoryDeepDestination()
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        Wagon wagon = getWagon();

        if ( wagon.supportsDirectoryCopy() )
        {
            sourceFile = new File( FileTestUtils.getTestOutputDir(), "deep0/deep1/deep2" );

            FileUtils.deleteDirectory( sourceFile );

            writeTestFile( "test-resource-1.txt" );
            writeTestFile( "a/test-resource-2.txt" );
            writeTestFile( "a/b/test-resource-3.txt" );
            writeTestFile( "c/test-resource-4.txt" );
            writeTestFile( "d/e/f/test-resource-5.txt" );

            wagon.connect( testRepository, getAuthInfo() );

            wagon.putDirectory( sourceFile, "deep0/deep1/deep2" );

            destFile = getTestFile( getName() + ".txt" );
            destFile.deleteOnExit();

            wagon.get( "deep0/deep1/deep2/test-resource-1.txt", destFile );
            wagon.get( "deep0/deep1/deep2/a/test-resource-2.txt", destFile );
            wagon.get( "deep0/deep1/deep2/a/b/test-resource-3.txt", destFile );
            wagon.get( "deep0/deep1/deep2/c/test-resource-4.txt", destFile );
            wagon.get( "deep0/deep1/deep2/d/e/f/test-resource-5.txt", destFile );

            wagon.disconnect();
        }

        tearDownWagonTestingFixtures();

        stopTestServer();
    }

    /**
     * Test that when putting a directory that already exists new files get also copied
     * 
     * @throws Exception
     * @since 1.0-beta-1
     */
    public void testWagonPutDirectoryWhenDirectoryAlreadyExists()
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        final String dirName = "directory-copy-existing";

        final String resourceToCreate = "test-resource-1.txt";

        final String[] resources = { "a/test-resource-2.txt", "a/b/test-resource-3.txt", "c/test-resource-4.txt" };

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        Wagon wagon = getWagon();

        if ( wagon.supportsDirectoryCopy() )
        {
            sourceFile = new File( FileTestUtils.getTestOutputDir(), dirName );

            FileUtils.deleteDirectory( sourceFile );

            createDirectory( wagon, resourceToCreate, dirName );

            for ( int i = 0; i < resources.length; i++ )
            {
                writeTestFile( resources[i] );
            }

            wagon.connect( testRepository, getAuthInfo() );

            wagon.putDirectory( sourceFile, dirName );

            List resourceNames = new ArrayList( resources.length + 1 );

            resourceNames.add( dirName + "/" + resourceToCreate );
            for ( int i = 0; i < resources.length; i++ )
            {
                resourceNames.add( dirName + "/" + resources[i] );
            }

            assertResourcesAreInRemoteSide( wagon, resourceNames );

            wagon.disconnect();
        }

        tearDownWagonTestingFixtures();

        stopTestServer();
    }

    /**
     * Test that when putting a directory that already exists new files get also copied and destination is "."
     * 
     * @throws Exception
     * @since 1.0-beta-1
     */
    public void testWagonPutDirectoryForDot()
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        final String resourceToCreate = "test-resource-1.txt";

        final String[] resources = { "a/test-resource-2.txt", "a/b/test-resource-3.txt", "c/test-resource-4.txt" };

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        Wagon wagon = getWagon();

        if ( wagon.supportsDirectoryCopy() )
        {
            sourceFile = new File( FileTestUtils.getTestOutputDir(), "dot-repo" );

            FileUtils.deleteDirectory( sourceFile );

            createDirectory( wagon, resourceToCreate, "." );

            for ( int i = 0; i < resources.length; i++ )
            {
                writeTestFile( resources[i] );
            }

            wagon.connect( testRepository, getAuthInfo() );

            wagon.putDirectory( sourceFile, "." );

            List resourceNames = new ArrayList( resources.length + 1 );

            resourceNames.add( resourceToCreate );
            for ( int i = 0; i < resources.length; i++ )
            {
                resourceNames.add( resources[i] );
            }

            assertResourcesAreInRemoteSide( wagon, resourceNames );

            wagon.disconnect();
        }

        tearDownWagonTestingFixtures();

        stopTestServer();
    }

    /**
     * Create a directory with a resource and check that the other ones don't exist
     * 
     * @param wagon
     * @param resourceToCreate
     *            name of the resource to be created
     * @param dirName
     *            directory name to create
     * @throws Exception
     */
    protected void createDirectory( final Wagon wagon, final String resourceToCreate, final String dirName )
        throws Exception
    {
        writeTestFile( resourceToCreate );
    }

    protected void assertResourcesAreInRemoteSide( final Wagon wagon, final List resourceNames )
        throws IOException, TransferFailedException, ResourceDoesNotExistException, AuthorizationException
    {
        Iterator iter = resourceNames.iterator();
        while ( iter.hasNext() )
        {
            String resourceName = (String) iter.next();

            File destFile = getTestFile( resourceName );
            destFile.deleteOnExit();

            wagon.get( resourceName, destFile );
        }
    }

    /**
     * Assert that a resource does not exist in the remote wagon system
     * 
     * @param wagon
     *            wagon to get the resource from
     * @param resourceName
     *            name of the resource
     * @throws IOException
     *             if a temp file can't be created
     * @throws AuthorizationException
     * @throws TransferFailedException
     * @since 1.0-beta-1
     */
    protected void assertNotExists( final Wagon wagon, final String resourceName )
        throws IOException, TransferFailedException, AuthorizationException
    {
        File tmpFile = File.createTempFile( "wagon", null );
        try
        {
            wagon.get( resourceName, tmpFile );
            fail( "Resource exists: " + resourceName );
        }
        catch ( ResourceDoesNotExistException e )
        {
            // ok
        }
        finally
        {
            tmpFile.delete();
        }
    }

    private void writeTestFile( final String child )
        throws IOException
    {
        File dir = new File( sourceFile, child );
        dir.getParentFile().mkdirs();
        FileUtils.fileWrite( dir.getAbsolutePath(), child );
    }

    public void testFailedGet()
        throws Exception
    {
        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        message( "Getting test artifact from test repository " + testRepository );

        Wagon wagon = getWagon();

        wagon.addTransferListener( checksumObserver );

        wagon.connect( testRepository, getAuthInfo() );

        destFile = getTestFile( getName() + ".txt" );
        destFile.deleteOnExit();

        try
        {
            wagon.get( "fubar.txt", destFile );
            fail( "File was found when it shouldn't have been" );
        }
        catch ( ResourceDoesNotExistException e )
        {
            // expected
            assertTrue( true );
        }
        finally
        {
            wagon.removeTransferListener( checksumObserver );

            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    public void testFailedGetIfNewer()
        throws Exception
    {
        if ( supportsGetIfNewer() )
        {
            alert( "\n\nRunning test: " + getName() );

            setupTestServer();

            setupRepositories();

            setupWagonTestingFixtures();

            message( "Getting test artifact from test repository " + testRepository );

            Wagon wagon = getWagon();
            wagon.addTransferListener( checksumObserver );
            wagon.connect( testRepository, getAuthInfo() );

            destFile = getTestFile( getName() + ".txt" );
            destFile.deleteOnExit();

            try
            {
                wagon.getIfNewer( "fubar.txt", destFile, 0 );
                fail( "File was found when it shouldn't have been" );
            }
            catch ( ResourceDoesNotExistException e )
            {
                // expected
                assertTrue( true );
            }
            finally
            {
                wagon.removeTransferListener( checksumObserver );

                wagon.disconnect();

                tearDownWagonTestingFixtures();

                stopTestServer();
            }
        }
    }

    /**
     * Test {@link Wagon#getFileList(String)}.
     * 
     * @throws Exception
     * @since 1.0-beta-2
     */
    public void testWagonGetFileList()
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        String dirName = "file-list";

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

    /**
     * Test {@link Wagon#getFileList(String)} when the directory does not exist.
     * 
     * @throws Exception
     * @since 1.0-beta-2
     */
    public void testWagonGetFileListWhenDirectoryDoesNotExist()
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        String dirName = "file-list-unexisting";

        Wagon wagon = getWagon();

        wagon.connect( testRepository, getAuthInfo() );

        try
        {
            wagon.getFileList( dirName );
            fail( "getFileList on unexisting directory must throw ResourceDoesNotExistException" );
        }
        catch ( ResourceDoesNotExistException e )
        {
            // expected
        }
        finally
        {
            wagon.disconnect();

            tearDownWagonTestingFixtures();

            stopTestServer();
        }
    }

    /**
     * Test for an existing resource.
     * 
     * @throws Exception
     * @since 1.0-beta-2
     */
    public void testWagonResourceExists()
        throws Exception
    {
        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        Wagon wagon = getWagon();

        putFile();

        wagon.connect( testRepository, getAuthInfo() );

        assertTrue( sourceFile.getName() + " does not exist", wagon.resourceExists( sourceFile.getName() ) );

        wagon.disconnect();

        tearDownWagonTestingFixtures();

        stopTestServer();
    }

    /**
     * Test for an invalid resource.
     * 
     * @throws Exception
     * @since 1.0-beta-2
     */
    public void testWagonResourceNotExists()
        throws Exception
    {
        alert( "\n\nRunning test: " + getName() );

        setupTestServer();

        setupRepositories();

        setupWagonTestingFixtures();

        Wagon wagon = getWagon();

        wagon.connect( testRepository, getAuthInfo() );

        assertFalse( wagon.resourceExists( "a/bad/resource/name/that/should/not/exist.txt" ) );

        wagon.disconnect();

        tearDownWagonTestingFixtures();

        stopTestServer();
    }

    // ----------------------------------------------------------------------
    // File <--> File round trip testing
    // ----------------------------------------------------------------------
    // We are testing taking a file, our sourcefile, and placing it into the
    // test repository that we have setup.
    // ----------------------------------------------------------------------

    protected void putFile( final String resourceName, final String testFileName, final String content )
        throws Exception
    {
        sourceFile = new File( FileTestUtils.getTestOutputDir(), testFileName );
        sourceFile.getParentFile().mkdirs();
        FileUtils.fileWrite( sourceFile.getAbsolutePath(), content );

        Wagon wagon = getWagon();

        ProgressArgumentMatcher progressArgumentMatcher = replayMockForPut( resourceName, content, wagon );

        message( "Putting test artifact: " + resourceName + " into test repository " + testRepository );

        connectWagon( wagon );

        wagon.put( sourceFile, resourceName );

        disconnectWagon( wagon );

        verifyMock( progressArgumentMatcher, content.length() );
    }

    protected ProgressArgumentMatcher replayMockForPut( final String resourceName, final String content,
                                                        final Wagon wagon )
    {
        Resource resource = new Resource( resourceName );
        mockTransferListener.transferInitiated( createTransferEvent( wagon, resource, TransferEvent.TRANSFER_INITIATED,
                                                                     TransferEvent.REQUEST_PUT, sourceFile ) );
        resource = new Resource( resourceName );
        resource.setContentLength( content.length() );
        resource.setLastModified( sourceFile.lastModified() );
        mockTransferListener.transferStarted( createTransferEvent( wagon, resource, TransferEvent.TRANSFER_STARTED,
                                                                   TransferEvent.REQUEST_PUT, sourceFile ) );
        mockTransferListener.transferProgress( createTransferEvent( wagon, resource, TransferEvent.TRANSFER_PROGRESS,
                                                                    TransferEvent.REQUEST_PUT, sourceFile ),
                                               new byte[] {}, 0 );
        ProgressArgumentMatcher progressArgumentMatcher = new ProgressArgumentMatcher();
        mockTransferListenerControl.setMatcher( progressArgumentMatcher );

        mockTransferListener.debug( null );
        mockTransferListenerControl.setMatcher( MockControl.ALWAYS_MATCHER );
        mockTransferListenerControl.setVoidCallable( MockControl.ZERO_OR_MORE );

        mockTransferListener.transferCompleted( createTransferEvent( wagon, resource, TransferEvent.TRANSFER_COMPLETED,
                                                                     TransferEvent.REQUEST_PUT, sourceFile ) );

        mockTransferListenerControl.replay();
        return progressArgumentMatcher;
    }

    protected TransferEvent createTransferEvent( final Wagon wagon, final Resource resource, final int eventType,
                                                 final int requestType, final File file )
    {
        TransferEvent transferEvent = new TransferEvent( wagon, resource, eventType, requestType );
        transferEvent.setLocalFile( file );
        return transferEvent;
    }

    protected int putFile()
        throws Exception
    {
        String content = "test-resource.txt\n";
        putFile( resource, "test-resource", content );
        return content.length();
    }

    protected void getFile( final int expectedSize )
        throws Exception
    {
        destFile = getTestFile( getName() + ".txt" );
        destFile.deleteOnExit();

        Wagon wagon = getWagon();

        ProgressArgumentMatcher progressArgumentMatcher = replaceMockForGet( wagon, expectedSize );

        message( "Getting test artifact from test repository " + testRepository );

        connectWagon( wagon );

        wagon.get( this.resource, destFile );

        disconnectWagon( wagon );

        verifyMock( progressArgumentMatcher, expectedSize );
    }

    protected void verifyMock( final ProgressArgumentMatcher progressArgumentMatcher, final int length )
    {
        mockTransferListenerControl.verify();

        assertEquals( length, progressArgumentMatcher.getSize() );

        mockTransferListenerControl.reset();
    }

    protected void disconnectWagon( final Wagon wagon )
        throws ConnectionException
    {
        wagon.removeTransferListener( mockTransferListener );

        wagon.removeTransferListener( checksumObserver );

        wagon.disconnect();
    }

    protected void connectWagon( final Wagon wagon )
        throws ConnectionException, AuthenticationException
    {
        wagon.addTransferListener( checksumObserver );

        wagon.addTransferListener( mockTransferListener );

        wagon.connect( testRepository, getAuthInfo() );
    }

    protected ProgressArgumentMatcher replaceMockForGet( final Wagon wagon, final int expectedSize )
    {
        Resource resource = new Resource( this.resource );
        mockTransferListener.transferInitiated( createTransferEvent( wagon, resource, TransferEvent.TRANSFER_INITIATED,
                                                                     TransferEvent.REQUEST_GET, destFile ) );
        resource = new Resource( this.resource );
        resource.setContentLength( getExpectedContentLengthOnGet( expectedSize ) );
        resource.setLastModified( getExpectedLastModifiedOnGet( testRepository, resource ) );
        mockTransferListener.transferStarted( createTransferEvent( wagon, resource, TransferEvent.TRANSFER_STARTED,
                                                                   TransferEvent.REQUEST_GET, destFile ) );
        mockTransferListener.transferProgress( new TransferEvent( wagon, resource, TransferEvent.TRANSFER_PROGRESS,
                                                                  TransferEvent.REQUEST_GET ), new byte[] {}, 0 );
        ProgressArgumentMatcher progressArgumentMatcher = new ProgressArgumentMatcher();
        mockTransferListenerControl.setMatcher( progressArgumentMatcher );

        mockTransferListener.debug( null );
        mockTransferListenerControl.setMatcher( MockControl.ALWAYS_MATCHER );
        mockTransferListenerControl.setVoidCallable( MockControl.ZERO_OR_MORE );

        mockTransferListener.transferCompleted( createTransferEvent( wagon, resource, TransferEvent.TRANSFER_COMPLETED,
                                                                     TransferEvent.REQUEST_GET, destFile ) );

        mockTransferListenerControl.replay();
        return progressArgumentMatcher;
    }

    protected int getExpectedContentLengthOnGet( final int expectedSize )
    {
        return expectedSize;
    }

    protected long getExpectedLastModifiedOnGet( final Repository repository, final Resource resource )
    {
        // default implementation - prone to failing if the time between test file creation and completion of putFile()
        // cross the "second" boundary, causing the "remote" and local files to have different times.

        return sourceFile.lastModified();
    }

    protected void fileRoundTripTesting()
        throws Exception
    {
        message( "File round trip testing ..." );

        int expectedSize = putFile();

        assertNotNull( "check checksum is not null", checksumObserver.getActualChecksum() );

        assertEquals( "compare checksums", "6b144b7285ffd6b0bc8300da162120b9", checksumObserver.getActualChecksum() );

        checksumObserver = new ChecksumObserver();

        getFile( expectedSize );

        assertNotNull( "check checksum is not null", checksumObserver.getActualChecksum() );

        assertEquals( "compare checksums", "6b144b7285ffd6b0bc8300da162120b9", checksumObserver.getActualChecksum() );

        // Now compare the conents of the artifact that was placed in
        // the repository with the contents of the artifact that was
        // retrieved from the repository.

        String sourceContent = FileUtils.fileRead( sourceFile );

        String destContent = FileUtils.fileRead( destFile );

        assertEquals( sourceContent, destContent );
    }

    // ----------------------------------------------------------------------
    //
    // ----------------------------------------------------------------------

    protected Repository createFileRepository( final String url )
    {
        File path = new File( url.substring( 7 ) );

        path.mkdirs();

        Repository repository = new Repository();

        repository.setUrl( url );

        return repository;
    }

}
