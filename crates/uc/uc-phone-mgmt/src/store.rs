//! Phone storage trait for persistence backends.

use crate::error::PhoneMgmtError;
use crate::model::{Phone, PhoneFilter};

/// Async storage backend for phone records.
pub trait PhoneStore: Send + Sync {
    /// Create a new phone record.
    fn create_phone(
        &self,
        phone: Phone,
    ) -> impl std::future::Future<Output = Result<Phone, PhoneMgmtError>> + Send;

    /// Get a phone by its unique ID.
    fn get_phone(
        &self,
        id: &str,
    ) -> impl std::future::Future<Output = Result<Phone, PhoneMgmtError>> + Send;

    /// Get a phone by its MAC address.
    fn get_phone_by_mac(
        &self,
        mac: &str,
    ) -> impl std::future::Future<Output = Result<Phone, PhoneMgmtError>> + Send;

    /// List phones matching the given filter criteria.
    fn list_phones(
        &self,
        filter: &PhoneFilter,
    ) -> impl std::future::Future<Output = Result<Vec<Phone>, PhoneMgmtError>> + Send;

    /// Update an existing phone record.
    fn update_phone(
        &self,
        phone: Phone,
    ) -> impl std::future::Future<Output = Result<Phone, PhoneMgmtError>> + Send;

    /// Delete a phone by its unique ID.
    fn delete_phone(
        &self,
        id: &str,
    ) -> impl std::future::Future<Output = Result<(), PhoneMgmtError>> + Send;

    /// Count phones matching the given filter criteria.
    fn count_phones(
        &self,
        filter: &PhoneFilter,
    ) -> impl std::future::Future<Output = Result<usize, PhoneMgmtError>> + Send;
}
