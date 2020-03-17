use log::*;
use parity_crypto::publickey::Secret;
use parity_path::restrict_permissions_owner;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// An entity that can be persisted on disk.
pub trait DiskEntity: Sized {
	const FILENAME: &'static str;
	/// Description of what kind of data that is stored in the file
	const DESCRIPTION: &'static str;

	/// Convert to string representation that will be written to disk.
	fn to_repr(&self) -> String;

	/// Convert from string representation loaded from disk.
	fn from_repr(s: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>>;
}

impl DiskEntity for Secret {
	const FILENAME: &'static str = "key";
	const DESCRIPTION: &'static str = "key file";

	fn to_repr(&self) -> String {
		self.to_hex()
	}

	fn from_repr(s: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
		Ok(s.parse()?)
	}
}

pub(crate) fn save<E: DiskEntity>(path: &Path, entity: &E) {
	let mut path_buf = PathBuf::from(path);
	if let Err(e) = fs::create_dir_all(path_buf.as_path()) {
		warn!("Error creating {} directory: {:?}", E::DESCRIPTION, e);
		return;
	};
	path_buf.push(E::FILENAME);
	let path = path_buf.as_path();
	let mut file = match fs::File::create(&path) {
		Ok(file) => file,
		Err(e) => {
			warn!("Error creating {}: {:?}", E::DESCRIPTION, e);
			return;
		}
	};
	if let Err(e) = restrict_permissions_owner(path, true, false) {
		warn!(target: "network", "Failed to modify permissions of the file ({})", e);
	}
	if let Err(e) = file.write(&entity.to_repr().into_bytes()) {
		warn!("Error writing {}: {:?}", E::DESCRIPTION, e);
	}
}

pub(crate) fn load<E>(path: &Path) -> Option<E>
where
	E: DiskEntity,
{
	let mut path_buf = PathBuf::from(path);
	path_buf.push(E::FILENAME);
	let mut file = fs::File::open(path_buf.as_path()).map_err(|e| debug!("Error opening {}: {:?}", E::DESCRIPTION, e)).ok()?;

	let mut buf = String::new();
	file.read_to_string(&mut buf).map_err(|e| warn!("Error reading {}: {:?}", E::DESCRIPTION, e)).ok()?;

	let data = E::from_repr(&buf).map_err(|e| warn!("Error parsing {}: {:?}", E::DESCRIPTION, e)).ok()?;

	Some(data)
}

#[cfg(test)]
mod tests {
	#[test]
	fn key_save_load() {
		use super::*;
		use ethereum_types::H256;
		use tempfile::TempDir;

		let tempdir = TempDir::new().unwrap();
		let key = Secret::from(H256::random());
		save(tempdir.path(), &key);
		let r = load(tempdir.path());
		assert_eq!(key, r.unwrap());
	}
}