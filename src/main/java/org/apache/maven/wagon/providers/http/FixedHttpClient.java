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

import java.lang.reflect.Field;

import org.apache.maven.wagon.providers.http.JettyClientHttpWagon.WagonExchange;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.util.LazyList;
import org.eclipse.jetty.util.component.LifeCycle;
import org.eclipse.jetty.util.thread.Timeout.Task;

class FixedHttpClient
    extends HttpClient
{

    WagonExchange _httpExchange;

    @Override
    public void removeLifeCycleListener( Listener listener )
    {
        // see https://bugs.eclipse.org/bugs/show_bug.cgi?id=296569
        _listeners = (LifeCycle.Listener[]) LazyList.removeFromArray( _listeners, listener );
    }

    @Override
    public void schedule( Task task )
    {
        super.schedule( task );

        // hack/workaround for https://bugs.eclipse.org/bugs/show_bug.cgi?id=296650
        if ( _httpExchange != null )
        {
            _httpExchange.setTimeoutTask( task );
        }
    }

    public void setKeyStoreType( String value )
    {
        setField( "_keyStoreType", value );
    }

    public void setKeyManagerAlgorithm( String value )
    {
        setField( "_keyManagerAlgorithm", ( value != null ) ? value : "SunX509" );
    }

    public void setTrustStoreType( String value )
    {
        setField( "_trustStoreType", value );
    }

    public void setTrustManagerAlgorithm( String value )
    {
        setField( "_trustManagerAlgorithm", ( value != null ) ? value : "SunX509" );
    }

    private void setField( String name, String value )
    {
        try
        {
            Field field = HttpClient.class.getDeclaredField( name );
            field.setAccessible( true );
            field.set( this, value );
        }
        catch ( Exception e )
        {
            throw new IllegalStateException( e );
        }
    }

}
