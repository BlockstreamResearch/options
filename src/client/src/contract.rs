//! Operations on all intialized contracts
use std::collections::BTreeMap;

use options_lib::miniscript::elements::hashes::sha256;
use options_lib::OptionsContract;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptionsBook {
    /// All open options along with Id
    pub book: BTreeMap<sha256::Hash, OptionsContract>,
}

impl OptionsBook {
    /// Creates a new [`OptionsBook`].
    pub fn new(book: BTreeMap<sha256::Hash, OptionsContract>) -> Self {
        Self { book }
    }

    /// Gets the contract from the book. Panic if the contract is not found
    pub fn get(&self, id: &sha256::Hash) -> &OptionsContract {
        self.book.get(id).expect("Contract not found in book")
    }
}
