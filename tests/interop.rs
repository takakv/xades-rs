use asice::Container;

use xades::{validate, DataObject, ValidationOptions};

// Containers from https://github.com/open-eid/SiVa
const BDOC_TM_2_SIG: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/bdoc_tm_valid_2_signatures.asice"
);

const ASICE_XADES_T: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/asiceWithXades-t-level.asice"
);

fn data_objects(container: &Container) -> Vec<DataObject<'_>> {
    container
        .data_files()
        .iter()
        .map(|f| DataObject {
            name: &f.name,
            mime_type: &f.mime_type,
            content: &f.content,
        })
        .collect()
}

fn trust_options() -> ValidationOptions {
    let mut options = ValidationOptions::default();
    options
        .add_trusted_pem(include_bytes!("fixtures/test_roots.pem"))
        .unwrap();
    options
}

#[test]
fn validates_bdoc_tm_container() {
    let container = Container::open_file(BDOC_TM_2_SIG).unwrap();
    let files = data_objects(&container);
    assert_eq!(container.signatures().len(), 2);

    for signature in container.signatures() {
        let results = validate(&signature.xml, &files, &trust_options()).unwrap();
        assert_eq!(results.len(), 1);
        let sig = &results[0];
        assert!(
            sig.is_valid(),
            "errors: {:?}, warnings: {:?}",
            sig.errors,
            sig.warnings
        );
    }
}

#[test]
fn validates_xades_t_container() {
    let container = Container::open_file(ASICE_XADES_T).unwrap();
    let files = data_objects(&container);
    assert_eq!(container.signatures().len(), 1);

    let results = validate(&container.signatures()[0].xml, &files, &trust_options()).unwrap();
    assert_eq!(results.len(), 1);
    let sig = &results[0];
    assert!(
        sig.is_valid(),
        "errors: {:?}, warnings: {:?}",
        sig.errors,
        sig.warnings
    );
}
