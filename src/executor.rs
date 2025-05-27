use parking_lot::Mutex;
use std::sync::Arc;
use tokio::runtime::Handle;
use tokio::task::{AbortHandle, JoinSet};

pub trait TokioExecutor: Clone + Send + Sync + 'static {
    fn spawn<F>(&self, f: F) -> AbortHandle
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static;
}

#[derive(Clone)]
pub struct DefaultTokioExecutor {
    handle: Handle,
}
impl DefaultTokioExecutor {
    pub fn new(handle: Handle) -> Self {
        Self { handle }
    }
}
impl Default for DefaultTokioExecutor {
    fn default() -> Self {
        Self::new(Handle::current())
    }
}

impl TokioExecutor for DefaultTokioExecutor {
    fn spawn<F>(&self, f: F) -> AbortHandle
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.handle.spawn(f).abort_handle()
    }
}

#[derive(Clone)]
pub struct JoinSetTokioExecutor {
    join_set: Arc<Mutex<JoinSet<()>>>,
}
impl JoinSetTokioExecutor {
    pub fn new(join_set: JoinSet<()>) -> Self {
        Self {
            join_set: Arc::new(Mutex::new(join_set)),
        }
    }
    pub fn abort_all(&self) {
        self.join_set.lock().abort_all();
    }
}

impl Default for JoinSetTokioExecutor {
    fn default() -> Self {
        Self::new(JoinSet::new())
    }
}

impl TokioExecutor for JoinSetTokioExecutor {
    fn spawn<F>(&self, f: F) -> AbortHandle
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.join_set.lock().spawn(async {
            f.await;
        })
    }
}

impl Drop for JoinSetTokioExecutor {
    fn drop(&mut self) {
        self.abort_all();
    }
}
