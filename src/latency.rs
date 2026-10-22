// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Server-side decision time: how long Risk Guard takes to answer a middleware request.
//!
//! OpenShell registers the middleware with a 500 ms timeout and fails closed, so the time Risk Guard adds to every inspected
//! request is the first thing a user of it needs to know. Samples go into fixed histogram buckets held in memory, and the
//! sidecar flushes one small row to SQLite every thirty seconds, so measuring adds nothing to the request path. The console
//! and `/metrics` merge the rows over a window; merged buckets give exact counts and conservative (bucket upper bound)
//! percentiles.
//!
//! What it measures: from the moment a request has passed validation to the moment its result is ready, including the
//! SQLite commit. What it does not: network transit between the supervisor and Risk Guard, or the supervisor's own time.

use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Upper bounds of the histogram buckets, in microseconds. A final overflow bucket holds everything above the last bound.
/// 500 ms is OpenShell's registered middleware timeout: the overflow bucket is "would have been cut off".
pub const BUCKET_BOUNDS_US: [u64; 11] = [
    250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000,
];

/// Samples accumulated over some interval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencyInterval {
    pub count: u64,
    pub sum_us: u64,
    pub max_us: u64,
    /// One count per bound, then the overflow bucket: `BUCKET_BOUNDS_US.len() + 1` entries.
    pub buckets: Vec<u64>,
}

impl Default for LatencyInterval {
    fn default() -> Self {
        Self {
            count: 0,
            sum_us: 0,
            max_us: 0,
            buckets: vec![0; BUCKET_BOUNDS_US.len() + 1],
        }
    }
}

impl LatencyInterval {
    pub fn record(&mut self, micros: u64) {
        let slot = BUCKET_BOUNDS_US
            .iter()
            .position(|bound| micros <= *bound)
            .unwrap_or(BUCKET_BOUNDS_US.len());
        self.buckets[slot] += 1;
        self.count += 1;
        self.sum_us = self.sum_us.saturating_add(micros);
        self.max_us = self.max_us.max(micros);
    }

    /// Add another interval's samples to this one. A malformed bucket list (wrong length) is ignored rather than guessed at.
    pub fn merge(&mut self, other: &Self) {
        if other.buckets.len() != self.buckets.len() {
            return;
        }
        for (mine, theirs) in self.buckets.iter_mut().zip(&other.buckets) {
            *mine += theirs;
        }
        self.count += other.count;
        self.sum_us = self.sum_us.saturating_add(other.sum_us);
        self.max_us = self.max_us.max(other.max_us);
    }

    /// The smallest bucket upper bound that covers `quantile` of the samples, in microseconds. This never understates the
    /// true value. Samples in the overflow bucket are reported as the largest sample seen. `None` when there are no samples.
    pub fn quantile_upper_bound_us(&self, quantile: f64) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        let needed = ((self.count as f64) * quantile.clamp(0.0, 1.0))
            .ceil()
            .max(1.0) as u64;
        let mut seen = 0;
        for (slot, in_bucket) in self.buckets.iter().enumerate() {
            seen += in_bucket;
            if seen >= needed {
                return Some(BUCKET_BOUNDS_US.get(slot).copied().unwrap_or(self.max_us));
            }
        }
        Some(self.max_us)
    }

    /// Samples that took longer than the last bound (OpenShell's 500 ms timeout).
    pub fn over_timeout(&self) -> u64 {
        self.buckets.last().copied().unwrap_or(0)
    }
}

/// Collects samples from concurrent requests. Cloning an `Arc` shares one recorder.
#[derive(Debug, Default)]
pub struct LatencyRecorder {
    interval: Mutex<LatencyInterval>,
}

impl LatencyRecorder {
    pub fn record(&self, elapsed: Duration) {
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        if let Ok(mut interval) = self.interval.lock() {
            interval.record(micros);
        }
    }

    /// Hand back everything recorded so far and start a fresh interval.
    pub fn take(&self) -> LatencyInterval {
        self.interval
            .lock()
            .map(|mut interval| std::mem::take(&mut *interval))
            .unwrap_or_default()
    }
}

/// Records the time from its creation to its drop, on every way out of a function (success, error or timeout), so a slow
/// failure is counted and the figures cannot flatter the service.
pub struct LatencyTimer<'a> {
    recorder: Option<&'a LatencyRecorder>,
    started: std::time::Instant,
}

impl<'a> LatencyTimer<'a> {
    pub fn start(recorder: Option<&'a LatencyRecorder>) -> Self {
        Self {
            recorder,
            started: std::time::Instant::now(),
        }
    }
}

impl Drop for LatencyTimer<'_> {
    fn drop(&mut self) {
        if let Some(recorder) = self.recorder {
            recorder.record(self.started.elapsed());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_land_in_the_right_buckets_and_totals_add_up() {
        let mut iv = LatencyInterval::default();
        for micros in [100, 250, 251, 900, 4_000, 600_000] {
            iv.record(micros);
        }
        assert_eq!(iv.count, 6);
        assert_eq!(iv.max_us, 600_000);
        assert_eq!(iv.sum_us, 100 + 250 + 251 + 900 + 4_000 + 600_000);
        assert_eq!(
            iv.buckets[0], 2,
            "100 and 250 are within the first bound (inclusive)"
        );
        assert_eq!(iv.buckets[1], 1, "251 is in the second");
        assert_eq!(iv.buckets[2], 1, "900 is within 1 ms");
        assert_eq!(iv.buckets[4], 1, "4 ms is within 5 ms");
        assert_eq!(iv.over_timeout(), 1, "600 ms is past the 500 ms timeout");
        assert_eq!(iv.buckets.iter().sum::<u64>(), iv.count);
    }

    #[test]
    fn percentiles_are_conservative_upper_bounds() {
        let mut iv = LatencyInterval::default();
        for _ in 0..98 {
            iv.record(800); // within 1 ms
        }
        iv.record(7_000); // within 10 ms
        iv.record(40_000); // within 50 ms
        assert_eq!(iv.quantile_upper_bound_us(0.50), Some(1_000));
        assert_eq!(iv.quantile_upper_bound_us(0.98), Some(1_000));
        assert_eq!(iv.quantile_upper_bound_us(0.99), Some(10_000));
        assert_eq!(iv.quantile_upper_bound_us(1.0), Some(50_000));
        assert!(
            iv.quantile_upper_bound_us(0.5).unwrap() >= 800,
            "never understates"
        );
        assert_eq!(
            LatencyInterval::default().quantile_upper_bound_us(0.5),
            None
        );
    }

    #[test]
    fn the_overflow_bucket_reports_the_largest_sample_not_a_made_up_bound() {
        let mut iv = LatencyInterval::default();
        iv.record(900_000);
        assert_eq!(iv.quantile_upper_bound_us(0.99), Some(900_000));
    }

    #[test]
    fn merging_intervals_adds_them_and_ignores_a_malformed_one() {
        let mut a = LatencyInterval::default();
        a.record(100);
        let mut b = LatencyInterval::default();
        b.record(3_000);
        b.record(900_000);
        a.merge(&b);
        assert_eq!((a.count, a.max_us, a.over_timeout()), (3, 900_000, 1));
        let bad = LatencyInterval {
            count: 99,
            sum_us: 1,
            max_us: 1,
            buckets: vec![1, 2],
        };
        a.merge(&bad);
        assert_eq!(
            a.count, 3,
            "a wrong-length bucket list is dropped, not guessed at"
        );
    }

    #[test]
    fn the_recorder_and_timer_hand_back_what_was_recorded_and_reset() {
        let recorder = LatencyRecorder::default();
        {
            let _timer = LatencyTimer::start(Some(&recorder));
            std::thread::sleep(Duration::from_millis(3));
        }
        let first = recorder.take();
        assert_eq!(first.count, 1);
        assert!(
            first.max_us >= 3_000,
            "the timer measured the sleep: {}",
            first.max_us
        );
        assert_eq!(recorder.take().count, 0, "taking resets the interval");
        drop(LatencyTimer::start(None)); // no recorder: nothing happens
    }
}
