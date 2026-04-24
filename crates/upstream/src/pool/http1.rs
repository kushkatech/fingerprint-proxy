use std::collections::VecDeque;

pub trait KeepAliveConnection {
    fn can_reuse(&self) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Http1ReleaseOutcome {
    Pooled,
    DiscardedNotReusable,
    DiscardedPoolFull,
}

#[derive(Debug)]
pub struct Http1ConnectionPool<C> {
    idle: VecDeque<C>,
    max_idle: usize,
}

impl<C: KeepAliveConnection> Http1ConnectionPool<C> {
    pub fn new(max_idle: usize) -> Self {
        Self {
            idle: VecDeque::new(),
            max_idle,
        }
    }

    pub fn max_idle(&self) -> usize {
        self.max_idle
    }

    pub fn idle_len(&self) -> usize {
        self.idle.len()
    }

    pub fn is_empty(&self) -> bool {
        self.idle.is_empty()
    }

    pub fn try_acquire(&mut self) -> Option<C> {
        while let Some(connection) = self.idle.pop_front() {
            if connection.can_reuse() {
                return Some(connection);
            }
        }
        None
    }

    pub fn release(&mut self, connection: C) -> Http1ReleaseOutcome {
        if !connection.can_reuse() {
            return Http1ReleaseOutcome::DiscardedNotReusable;
        }
        if self.idle.len() >= self.max_idle {
            return Http1ReleaseOutcome::DiscardedPoolFull;
        }
        self.idle.push_back(connection);
        Http1ReleaseOutcome::Pooled
    }
}
