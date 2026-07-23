use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock as AsyncRwLock};

#[derive(Clone, Default)]
pub(crate) struct MaintenanceGate {
    synchronous: Arc<RwLock<()>>,
    asynchronous: Arc<AsyncRwLock<()>>,
}

impl MaintenanceGate {
    pub(crate) fn mutation(&self) -> RwLockReadGuard<'_, ()> {
        self.synchronous
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) async fn mutation_async(&self) -> OwnedRwLockReadGuard<()> {
        self.asynchronous.clone().read_owned().await
    }

    pub(crate) fn maintenance(&self) -> RwLockWriteGuard<'_, ()> {
        self.synchronous
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) async fn maintenance_async(&self) -> OwnedRwLockWriteGuard<()> {
        self.asynchronous.clone().write_owned().await
    }
}
