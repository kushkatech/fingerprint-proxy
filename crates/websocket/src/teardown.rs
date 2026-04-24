#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketPeer {
    Client,
    Upstream,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WebSocketConnectionTeardown {
    client_close_seen: bool,
    upstream_close_seen: bool,
    client_eof_seen: bool,
    upstream_eof_seen: bool,
}

impl WebSocketConnectionTeardown {
    pub fn note_close_frame(&mut self, peer: WebSocketPeer) {
        match peer {
            WebSocketPeer::Client => self.client_close_seen = true,
            WebSocketPeer::Upstream => self.upstream_close_seen = true,
        }
    }

    pub fn note_eof(&mut self, peer: WebSocketPeer) {
        match peer {
            WebSocketPeer::Client => self.client_eof_seen = true,
            WebSocketPeer::Upstream => self.upstream_eof_seen = true,
        }
    }

    pub fn should_shutdown(self) -> bool {
        (self.client_close_seen && self.upstream_close_seen)
            || self.client_eof_seen
            || self.upstream_eof_seen
    }
}
