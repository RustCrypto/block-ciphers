//! Implementation according to the [RC5 paper]
//! [RC5 paper]: https://www.grc.com/r&d/rc5.pdf

mod backend;
mod primitives;

pub use backend::RC5;
pub use primitives::*;
