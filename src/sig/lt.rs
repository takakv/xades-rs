use tsp_ltv::ltv::{ocsp_check_revocation, OcspClient, ValidationStatus};
use tsp_ltv::tsp::TsaClient;
use x509_cert::der::Decode;
use x509_cert::Certificate;

use crate::error::{LibError, Result};
use crate::CreatedSignature;

#[derive(Debug, Clone)]
pub struct LtConfig {
    /// RFC 3161 timestamping service URL.
    pub tsa_url: String,
    /// DER certificates completing the signer's chain.
    pub issuer_certs_der: Vec<Vec<u8>>,
}

impl CreatedSignature {
    async fn request_signature_timestamp(&self, tsa_url: &str) -> Result<Vec<u8>> {
        let input = self.timestamp_input()?;
        let digest_alg = tsp_ltv::crypto::algorithm::DigestAlgorithm::Sha256;
        let hash = digest_alg.digest(&input);
        TsaClient::new(tsa_url)
            .digest_algorithm(digest_alg)
            .timestamp(&hash)
            .await
            .map_err(|e| LibError::Timestamp(format!("TSA {tsa_url}: {e}")))
    }

    pub fn extend_to_t(self, tsa_url: &str) -> Result<CreatedSignature> {
        let token = runtime()?.block_on(self.request_signature_timestamp(tsa_url))?;
        self.extend_to_t_with(token)
    }

    pub fn extend_to_lt(self, config: &LtConfig) -> Result<CreatedSignature> {
        let leaf = Certificate::from_der(&self.draft.cert_der)
            .map_err(|e| LibError::Certificate(format!("signer certificate: {e}")))?;
        let issuer = find_issuer(&leaf, &config.issuer_certs_der)?;

        // Timestamp must predate OCSP response.
        let runtime = runtime()?;
        let token = runtime.block_on(self.request_signature_timestamp(&config.tsa_url))?;
        let ocsp_der = runtime.block_on(request_certificate_status(&leaf, &issuer))?;

        self.extend_to_lt_with(token, vec![ocsp_der], config.issuer_certs_der.clone())
    }
}

fn find_issuer(leaf: &Certificate, candidates_der: &[Vec<u8>]) -> Result<Certificate> {
    for der in candidates_der {
        let cert = Certificate::from_der(der)
            .map_err(|e| LibError::Certificate(format!("issuer certificate: {e}")))?;
        if cert.tbs_certificate.subject == leaf.tbs_certificate.issuer {
            return Ok(cert);
        }
    }
    Err(LibError::Certificate(format!(
        "no issuer certificate provided for {}",
        leaf.tbs_certificate.issuer
    )))
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| LibError::Signing(format!("tokio runtime: {e}")))
}

async fn request_certificate_status(leaf: &Certificate, issuer: &Certificate) -> Result<Vec<u8>> {
    let (ocsp_der, nonce) = OcspClient::new()
        .fetch_ocsp_response_with_nonce(leaf, issuer)
        .await
        .map_err(|e| LibError::Ocsp(format!("OCSP fetch: {e}")))?;
    match ocsp_check_revocation(&ocsp_der, leaf, issuer, Some(&nonce), None) {
        Ok(ValidationStatus::Valid { .. }) => {}
        Ok(other) => {
            return Err(LibError::Ocsp(format!(
                "signer certificate revocation status is not good: {other:?}"
            )));
        }
        Err(e) => return Err(LibError::Ocsp(format!("OCSP response invalid: {e}"))),
    }
    Ok(ocsp_der)
}
