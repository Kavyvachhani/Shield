pub mod cvss4;
// `MAX_SEVERITY_EQ5` is unused on purpose: the specification defines EQ5's
// percentage-to-next-severity as zero, so it contributes to the count of lower
// MacroVectors but never to the interpolated distance. The table is kept so this
// file stays a faithful transcription of the published constants.
#[rustfmt::skip]
#[allow(dead_code)]
mod cvss4_tables;
pub mod priority;

pub use cvss4::{Cvss4Error, Cvss4Severity, Cvss4Vector};
