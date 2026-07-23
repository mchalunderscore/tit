use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub(crate) struct AttemptLimiter<K> {
    inner: Arc<Mutex<AttemptState<K>>>,
    maximum: usize,
    window: Duration,
    maximum_keys: usize,
}

struct AttemptState<K> {
    attempts: HashMap<K, VecDeque<Instant>>,
}

impl<K> AttemptLimiter<K>
where
    K: Clone + Eq + Hash,
{
    pub(crate) fn new(maximum: usize, window: Duration, maximum_keys: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(AttemptState {
                attempts: HashMap::new(),
            })),
            maximum,
            window,
            maximum_keys,
        }
    }

    pub(crate) fn allow(&self, key: K) -> bool {
        let now = Instant::now();
        let Ok(mut state) = self.inner.lock() else {
            return false;
        };
        state.attempts.retain(|_, attempts| {
            while attempts
                .front()
                .is_some_and(|attempt| now.duration_since(*attempt) >= self.window)
            {
                attempts.pop_front();
            }
            !attempts.is_empty()
        });
        if !state.attempts.contains_key(&key) && state.attempts.len() >= self.maximum_keys {
            return false;
        }
        let attempts = state.attempts.entry(key).or_default();
        if attempts.len() >= self.maximum {
            return false;
        }
        attempts.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::AttemptLimiter;
    use std::time::Duration;

    #[test]
    fn bounds_attempts_and_tracked_keys() {
        let limiter = AttemptLimiter::new(2, Duration::from_secs(60), 2);
        assert!(limiter.allow("first"));
        assert!(limiter.allow("first"));
        assert!(!limiter.allow("first"));
        assert!(limiter.allow("second"));
        assert!(!limiter.allow("third"));
    }
}
