//! Real-time thread priority for audio threads.
//!
//! On macOS, uses `pthread_set_qos_class_self_np` to set the thread to
//! User-Interactive QoS, which the kernel schedules with the lowest
//! latency and highest priority (short of real-time Mach threads).
//!
//! On other platforms, this is a no-op.

use tracing::{debug, warn};

/// Promotes the calling thread to real-time priority.
///
/// On macOS, sets QoS to `QOS_CLASS_USER_INTERACTIVE` (value 0x21).
/// Returns `true` if the priority was set successfully.
#[allow(unsafe_code)]
pub(crate) fn set_realtime_priority(thread_name: &str) -> bool {
    #[cfg(target_os = "macos")]
    {
        // QOS_CLASS_USER_INTERACTIVE = 0x21 (from <sys/qos.h>)
        const QOS_CLASS_USER_INTERACTIVE: u32 = 0x21;

        unsafe extern "C" {
            fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
        }

        // SAFETY: pthread_set_qos_class_self_np is a well-defined macOS API
        // that modifies only the calling thread's scheduling attributes.
        // relative_priority=0 means "default within the class".
        let ret = unsafe { pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0) };
        if ret == 0 {
            debug!("Set {} thread to QOS_CLASS_USER_INTERACTIVE", thread_name);
            true
        } else {
            warn!("Failed to set {} thread QoS (errno={})", thread_name, ret);
            false
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = thread_name;
        debug!("Thread priority not supported on this platform");
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_realtime_priority() {
        // Should succeed on macOS, return false on other platforms
        let result = set_realtime_priority("test");
        #[cfg(target_os = "macos")]
        assert!(result);
        #[cfg(not(target_os = "macos"))]
        assert!(!result);
    }
}
