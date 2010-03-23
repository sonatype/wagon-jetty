package org.apache.maven.wagon.providers.http;

import java.io.IOException;
import java.io.InputStream;

class HugeInputStream
    extends InputStream
{

    private long size;

    private long read;

    public HugeInputStream( long size )
    {
        this.size = size;
    }

    public long getSize()
    {
        return size;
    }

    @Override
    public int read()
        throws IOException
    {
        if ( read >= size )
        {
            return -1;
        }
        read++;
        return 0;
    }

    @Override
    public int read( byte[] b, int off, int len )
        throws IOException
    {
        if ( read >= size )
        {
            return -1;
        }

        int avail = (int) Math.min( len, size - read );

        read += avail;

        return avail;
    }

}
