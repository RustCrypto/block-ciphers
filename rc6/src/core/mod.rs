//! Implementation according to the [RC6 paper]
//! [RC6 paper]: https://www.grc.com/r&d/rc6.pdf

mod backend;
mod primitives;

pub use backend::RC6;
pub use primitives::*;
