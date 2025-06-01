use parking_lot::Mutex;
use std::sync::{Arc, Weak};
use tokio::runtime::Handle;
use tokio::task::{AbortHandle, JoinSet};

pub trait TokioExecutorRef: Clone + Send + Sync + 'static {
    fn spawn<F>(&self, f: F) -> AbortHandle
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static;
}

pub trait TokioExecutor: TokioExecutorRef {
    type Ref: TokioExecutorRef;
    fn ref_clone(&self) -> Self::Ref;
}

// ///////////////////////////////
// Default TokioExecutor
// ///////////////////////////////
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

impl TokioExecutorRef for DefaultTokioExecutor {
    fn spawn<F>(&self, f: F) -> AbortHandle
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.handle.spawn(f).abort_handle()
    }
}

impl TokioExecutor for DefaultTokioExecutor {
    type Ref = DefaultTokioExecutor;

    fn ref_clone(&self) -> DefaultTokioExecutor {
        self.clone()
    }
}

// ///////////////////////////////
// JoinSetTokioExecutor
// ///////////////////////////////

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

impl Drop for JoinSetTokioExecutor {
    fn drop(&mut self) {
        self.abort_all();
    }
}
impl Default for JoinSetTokioExecutor {
    fn default() -> Self {
        Self::new(JoinSet::new())
    }
}

impl TokioExecutorRef for JoinSetTokioExecutor {
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

impl TokioExecutor for JoinSetTokioExecutor {
    type Ref = JoinSetTokioExecutorRef;

    fn ref_clone(&self) -> Self::Ref {
        JoinSetTokioExecutorRef::new(self)
    }
}

#[derive(Clone)]
pub struct JoinSetTokioExecutorRef {
    join_set: Weak<Mutex<JoinSet<()>>>,
    default_abort_handle: AbortHandle,
}
impl JoinSetTokioExecutorRef {
    fn new(exec: &JoinSetTokioExecutor) -> Self {
        let default_abort_handle = exec.join_set.lock().spawn(futures_util::future::pending());
        let join_set = Arc::downgrade(&exec.join_set);
        Self {
            join_set,
            default_abort_handle,
        }
    }
}

impl TokioExecutorRef for JoinSetTokioExecutorRef {
    fn spawn<F>(&self, f: F) -> AbortHandle
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.join_set
            .upgrade()
            .map(|l| {
                l.lock().spawn(async {
                    f.await;
                })
            })
            .unwrap_or_else(|| self.default_abort_handle.clone())
    }
}
