pub mod validate;

pub mod error;
mod ns;
mod xml;

pub use validate::{validate, Profile, SignatureValidation, ValidationOptions};

/// A data object covered by a signature.
#[derive(Debug, Clone, Copy)]
pub struct DataObject<'a> {
    /// File name as stored in the container.
    pub name: &'a str,
    /// Media type, e.g. `application/pdf`.
    pub mime_type: &'a str,
    /// Raw content.
    pub content: &'a [u8],
}
