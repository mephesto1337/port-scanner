use std::time::Duration;
use tokio::time;

pub(crate) async fn run_with_timeout<O>(
    timeout: Duration,
    fut: impl std::future::Future<Output = O>,
) -> Option<O> {
    let sleep = time::sleep(timeout);
    tokio::pin!(sleep);

    tokio::select! {
        ready = fut => {
            Some(ready)
        }
        _ = &mut sleep => {
            None
        }
    }
}
