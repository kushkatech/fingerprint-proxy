#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Http2InsertOutcome {
    Inserted,
    RejectedPoolFull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http2StreamLease {
    connection_index: usize,
}

impl Http2StreamLease {
    pub fn connection_index(&self) -> usize {
        self.connection_index
    }
}

#[derive(Debug)]
pub struct Http2PooledConnection<C> {
    connection: C,
    max_concurrent_streams: usize,
    active_streams: usize,
}

impl<C> Http2PooledConnection<C> {
    pub fn new(connection: C, max_concurrent_streams: usize) -> Self {
        Self {
            connection,
            max_concurrent_streams,
            active_streams: 0,
        }
    }

    pub fn max_concurrent_streams(&self) -> usize {
        self.max_concurrent_streams
    }

    pub fn active_streams(&self) -> usize {
        self.active_streams
    }

    pub fn available_streams(&self) -> usize {
        self.max_concurrent_streams
            .saturating_sub(self.active_streams)
    }

    pub fn has_capacity(&self) -> bool {
        self.active_streams < self.max_concurrent_streams
    }

    pub fn try_acquire_stream(&mut self) -> bool {
        if !self.has_capacity() {
            return false;
        }
        self.active_streams += 1;
        true
    }

    pub fn release_stream(&mut self) -> bool {
        if self.active_streams == 0 {
            return false;
        }
        self.active_streams -= 1;
        true
    }

    pub fn connection(&self) -> &C {
        &self.connection
    }

    pub fn connection_mut(&mut self) -> &mut C {
        &mut self.connection
    }

    pub fn into_inner(self) -> C {
        self.connection
    }
}

#[derive(Debug)]
pub struct Http2ConnectionPool<C> {
    connections: Vec<Http2PooledConnection<C>>,
    max_connections: usize,
}

impl<C> Http2ConnectionPool<C> {
    pub fn new(max_connections: usize) -> Self {
        Self {
            connections: Vec::new(),
            max_connections,
        }
    }

    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    pub fn insert_connection(
        &mut self,
        connection: Http2PooledConnection<C>,
    ) -> Http2InsertOutcome {
        if self.connections.len() >= self.max_connections {
            return Http2InsertOutcome::RejectedPoolFull;
        }
        self.connections.push(connection);
        Http2InsertOutcome::Inserted
    }

    pub fn try_acquire_stream(&mut self) -> Option<Http2StreamLease> {
        for (connection_index, connection) in self.connections.iter_mut().enumerate() {
            if connection.try_acquire_stream() {
                return Some(Http2StreamLease { connection_index });
            }
        }
        None
    }

    pub fn release_stream(&mut self, lease: Http2StreamLease) -> bool {
        self.connections
            .get_mut(lease.connection_index)
            .is_some_and(Http2PooledConnection::release_stream)
    }

    pub fn connection(&self, connection_index: usize) -> Option<&Http2PooledConnection<C>> {
        self.connections.get(connection_index)
    }
}
