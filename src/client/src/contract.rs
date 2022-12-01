//! Operations on all intialized contracts
use std::path::Path;

use options_lib::miniscript::elements::hashes::sha256;
use options_lib::OptionsContract;
use secp256k1::hashes::Hash;
use sled;

#[derive(Debug, Clone)]
pub struct OptionsBook {
    /// All open options along with Id
    pub book: sled::Db,
}

impl OptionsBook {
    /// Creates a new [`OptionsBook`].
    pub fn new(path: &Path) -> Self {
        Self {
            book: sled::open(path).unwrap(),
        }
    }

    /// Gets the contract from the book. Panic if the contract is not found
    pub fn get(&self, key: &sha256::Hash) -> Option<OptionsContract> {
        let res = self.book.get(&key).unwrap();
        res.map(|x| OptionsContract::from_slice(&x))
    }

    /// Inserts a contract into the book
    pub fn insert(&self, contract: &OptionsContract) {
        let key = contract.id();
        self.book
            .insert(key.as_inner(), contract.serialize())
            .unwrap();
    }

    /// Removes a contract from the book
    pub fn remove(&self, key: &sha256::Hash) {
        self.book.remove(&key).unwrap();
    }
}
