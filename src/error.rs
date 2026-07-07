use thiserror::Error;

#[derive(Error, Debug)]
pub enum LibError {
    #[error("certificate: {0}")]
    Certificate(String),
}

pub type Result<T> = std::result::Result<T, LibError>;
