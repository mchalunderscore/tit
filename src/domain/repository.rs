use thiserror::Error;

const MAX_SLUG_BYTES: usize = 100;
const RESERVED_SLUGS: [&str; 6] = ["admin", "api", "assets", "feeds", "issues", "setup"];

pub(crate) fn validate_slug(slug: &str) -> Result<(), RepositoryNameError> {
    if slug.is_empty()
        || slug.len() > MAX_SLUG_BYTES
        || slug.ends_with(".git")
        || RESERVED_SLUGS.contains(&slug)
        || !slug.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
        || !slug
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !slug
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(RepositoryNameError::InvalidSlug);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub(crate) enum RepositoryNameError {
    #[error("repository slug is not valid")]
    InvalidSlug,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_canonical_repository_slugs() {
        for slug in ["a", "tit", "tit.cde", "tit_cde", "tit-cde", "a.1_b-2"] {
            validate_slug(slug).expect("accept a canonical slug");
        }
    }

    #[test]
    fn rejects_aliases_routes_and_unsafe_repository_slugs() {
        for slug in [
            "", ".tit", "tit.", "Tit", "tit.git", "admin", "api", "a/b", "a b", "é",
        ] {
            assert!(validate_slug(slug).is_err(), "accepted {slug:?}");
        }
        assert!(validate_slug(&"a".repeat(101)).is_err());
    }
}
