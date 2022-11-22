use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::task::{Context, Poll, Waker};
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

const SLOT_FREE: bool = false;
const SLOT_OCCUPIED: bool = true;

pub struct Semaphore {
    /// occupied slots (false: slot is free, true: slot is already taken)
    tickets: Vec<AtomicBool>,

    /// wakers to wake whenever we have a release operation
    wakers: Mutex<VecDeque<Waker>>,
}

pub struct TicketFuture {
    sem: Arc<Semaphore>,
}

pub struct Ticket {
    slot: usize,
    sem: Arc<Semaphore>,
}

impl Semaphore {
    pub fn new(max: usize) -> Arc<Self> {
        debug_assert!(SLOT_FREE != SLOT_OCCUPIED);
        Arc::new(Self {
            tickets: (0..max).map(|_| AtomicBool::new(SLOT_FREE)).collect(),
            wakers: Mutex::new(VecDeque::new()),
        })
    }

    pub fn acquire(self: &Arc<Self>) -> TicketFuture {
        TicketFuture {
            sem: Arc::clone(self),
        }
    }
}

impl Future for TicketFuture {
    type Output = Ticket;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<<Self as Future>::Output> {
        let me = &*self;

        for (slot, abool) in me.sem.tickets.iter().enumerate() {
            if abool
                .compare_exchange_weak(
                    SLOT_FREE,
                    SLOT_OCCUPIED,
                    Ordering::Acquire,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                let sem = Arc::clone(&me.sem);
                return Poll::Ready(Ticket { slot, sem });
            }
        }

        let waker = cx.waker().clone();
        {
            let mut wakers = me.sem.wakers.lock().expect("Dead thread");
            wakers.push_back(waker);
        }

        Poll::Pending
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let previous = self.sem.tickets[self.slot].swap(SLOT_FREE, Ordering::Release);
        assert!(previous == SLOT_OCCUPIED);

        let mut wakers_lock = self.sem.wakers.lock().expect("Dead thread");
        if let Some(waker) = wakers_lock.pop_front() {
            waker.wake();
        }
    }
}
