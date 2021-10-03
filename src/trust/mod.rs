/// Trust
///
/// This modules handles parts for trust on users.
/// This primarily includes publication/search of PGP
/// certificates/identities
use async_graphql::MergedObject;

use self::certification::CertificationMutations;

pub mod certification;

#[derive(Default, MergedObject)]
pub struct TrustMutations(pub CertificationMutations);

#[derive(Default, MergedObject)]
pub struct TrustQueries();
