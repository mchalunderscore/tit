use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::auth::{AuthError, validate_username};
use crate::store::{OrganizationProfile, Store, StoreError};
use crate::system::{random_lower_hex, unix_timestamp};

const MAX_DISPLAY_NAME_BYTES: usize = 100;
const MAX_DESCRIPTION_BYTES: usize = 512;
const PROFILE_REPOSITORY_PAGE_SIZE: usize = 20;

#[derive(Clone)]
pub(crate) struct OrganizationService {
    database: PathBuf,
}

impl OrganizationService {
    pub(crate) fn new(database: &Path) -> Self {
        Self {
            database: database.to_owned(),
        }
    }

    pub(crate) fn create(
        &self,
        slug: &str,
        display_name: &str,
        description: &str,
        owner: &str,
    ) -> Result<(), OrganizationError> {
        validate_username(slug)?;
        validate_username(owner)?;
        validate_profile(display_name, description)?;
        Store::open(&self.database)?.create_organization(
            slug,
            display_name,
            description,
            owner,
            now()?,
            &correlation_id()?,
        )?;
        Ok(())
    }

    pub(crate) fn set_member(
        &self,
        organization: &str,
        actor: &str,
        username: &str,
        role: &str,
    ) -> Result<(), OrganizationError> {
        validate_context(organization, actor, username)?;
        Store::open(&self.database)?.set_organization_member(
            organization,
            actor,
            username,
            role,
            now()?,
            &correlation_id()?,
        )?;
        Ok(())
    }

    pub(crate) fn update_profile(
        &self,
        organization: &str,
        actor: &str,
        display_name: &str,
        description: &str,
    ) -> Result<(), OrganizationError> {
        validate_username(organization)?;
        validate_username(actor)?;
        validate_profile(display_name, description)?;
        Store::open(&self.database)?.update_organization_profile(
            organization,
            actor,
            display_name,
            description,
            now()?,
            &correlation_id()?,
        )?;
        Ok(())
    }

    pub(crate) fn can_manage(
        &self,
        organization: &str,
        username: &str,
    ) -> Result<bool, OrganizationError> {
        validate_username(organization)?;
        Ok(self
            .maintained_namespaces(username)?
            .iter()
            .any(|namespace| namespace == organization))
    }

    pub(crate) fn is_owner(
        &self,
        organization: &str,
        username: &str,
    ) -> Result<bool, OrganizationError> {
        validate_username(organization)?;
        validate_username(username)?;
        Ok(Store::open(&self.database)?
            .organization_member_role(organization, username)?
            .as_deref()
            == Some("owner"))
    }

    pub(crate) fn remove_member(
        &self,
        organization: &str,
        actor: &str,
        username: &str,
    ) -> Result<(), OrganizationError> {
        validate_context(organization, actor, username)?;
        Store::open(&self.database)?.remove_organization_member(
            organization,
            actor,
            username,
            now()?,
            &correlation_id()?,
        )?;
        Ok(())
    }

    pub(crate) fn profile_page(
        &self,
        slug: &str,
        page: usize,
    ) -> Result<OrganizationProfile, OrganizationError> {
        validate_username(slug)?;
        if page == 0 || page > 10_000 {
            return Err(OrganizationError::InvalidProfile);
        }
        let profile = Store::open(&self.database)?.organization_profile(
            slug,
            page,
            PROFILE_REPOSITORY_PAGE_SIZE,
        )?;
        if page > 1 && profile.repositories.is_empty() {
            return Err(OrganizationError::InvalidProfile);
        }
        Ok(profile)
    }

    pub(crate) fn maintained_namespaces(
        &self,
        username: &str,
    ) -> Result<Vec<String>, OrganizationError> {
        validate_username(username)?;
        Store::open(&self.database)?
            .maintained_namespaces(username)
            .map_err(Into::into)
    }
}

fn validate_context(
    organization: &str,
    actor: &str,
    username: &str,
) -> Result<(), OrganizationError> {
    validate_username(organization)?;
    validate_username(actor)?;
    validate_username(username)?;
    Ok(())
}

fn validate_profile(display_name: &str, description: &str) -> Result<(), OrganizationError> {
    if display_name.is_empty()
        || display_name.len() > MAX_DISPLAY_NAME_BYTES
        || description.len() > MAX_DESCRIPTION_BYTES
        || display_name.chars().any(char::is_control)
        || description
            .chars()
            .any(|character| character.is_control() && character != '\n')
    {
        return Err(OrganizationError::InvalidProfile);
    }
    Ok(())
}

fn now() -> Result<i64, OrganizationError> {
    unix_timestamp().ok_or(OrganizationError::Clock)
}

fn correlation_id() -> Result<String, OrganizationError> {
    random_lower_hex::<16>().ok_or(OrganizationError::Random)
}

#[derive(Debug, Error)]
pub(crate) enum OrganizationError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("organization profile is not valid")]
    InvalidProfile,
    #[error("the clock is not available")]
    Clock,
    #[error("random data is not available")]
    Random,
}
