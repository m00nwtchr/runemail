use std::{
	collections::HashMap,
	fmt,
	path::{Path, PathBuf},
	sync::{Arc, RwLock},
};

use enum_dispatch::enum_dispatch;
use inotify::{EventMask, Inotify, WatchMask};
use sequoia_openpgp::{
	Cert, Fingerprint, parse::Parse, policy::StandardPolicy, types::HashAlgorithm,
};
use thiserror::Error;
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;

/// Type alias for results returned by this module
pub type Result<T> = std::result::Result<T, KeyError>;

/// Custom error type for key-related operations
#[derive(Error, Debug)]
pub enum KeyError {
	#[error("key not found")]
	KeyNotFound,
	#[error("file not found")]
	FileNotFound,
	#[error(transparent)]
	Other(#[from] sequoia_openpgp::anyhow::Error),
}

/// Represents an email address broken into components
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EmailComponents {
	/// The encoded local part of the email (32-character hash)
	encoded_local: String,
	/// The original local part of the email
	local_part: String,
	/// The domain part of the email
	domain: String,
}

#[enum_dispatch]
pub trait KeyProvider {
	/// Discovers a certificate based on the hashed local part and domain of an email
	fn discover<S: AsRef<str>>(&self, hashed: S, domain: S) -> Option<Cert>;
}

#[enum_dispatch(KeyProvider)]
pub enum KeyProviderType {
	FileKeyProvider(FileKeyProvider),
}

/// Stores and manages PGP certificates
#[derive(Default)]
pub struct KeyStore {
	keys: HashMap<Fingerprint, Cert>,
	uids: HashMap<EmailComponents, Fingerprint>,
	files: HashMap<PathBuf, Fingerprint>,
}

/// Returns a 32-character string from the local part of an email address
///
/// From [draft-koch]:
///     The so-mapped local-part is hashed using the SHA-1 algorithm. The
///     resulting 160-bit digest is encoded using the Z-Base-32 method as
///     described in RFC6189, section 5.1.6. The resulting string has a
///     fixed length of 32 octets.
fn encode_local_part<S: AsRef<str>>(local_part: S) -> String {
	let local_part = local_part.as_ref();
	let mut digest = vec![0; 20];
	let mut ctx = HashAlgorithm::SHA1
		.context()
		.expect("must be implemented")
		.for_digest();
	ctx.update(local_part.as_bytes());
	let _ = ctx.digest(&mut digest);
	// After z-base-32 encoding 20 bytes, it will be 32 bytes long.
	zbase32::encode(&digest[..], 160)
}

impl KeyStore {
	/// Loads a certificate from a file path and stores it
	pub fn load<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
		let cert = Cert::from_file(&path)?;
		let fp = cert.fingerprint();
		self.import(cert)?;
		self.files.insert(path.as_ref().to_path_buf(), fp);
		Ok(())
	}

	/// Removes a certificate associated with a file path
	pub fn unload<P: AsRef<Path>>(&mut self, path: P) -> Result<Cert> {
		let fp = self
			.files
			.remove(&path.as_ref().to_path_buf())
			.ok_or(KeyError::FileNotFound)?;
		self.delete(&fp)
	}

	/// Removes a certificate by fingerprint
	pub fn delete(&mut self, fp: &Fingerprint) -> Result<Cert> {
		let key = self.keys.remove(fp).ok_or(KeyError::KeyNotFound)?;
		self.uids.retain(|_, v| v != fp);
		Ok(key)
	}

	/// Processes an email address into components for storage
	fn process_email(&mut self, email: &str, fp: &Fingerprint) -> Option<()> {
		let (local_part, domain) = email.split_once('@')?;
		let email_components = EmailComponents {
			encoded_local: encode_local_part(local_part),
			local_part: local_part.to_string(),
			domain: domain.to_string(),
		};
		self.uids.insert(email_components, fp.clone());
		Some(())
	}

	/// Imports a certificate into the store
	pub fn import(&mut self, key: Cert) -> Result<()> {
		let key = key.strip_secret_key_material();
		let fp = key.fingerprint();

		// Extract valid user IDs with a policy check
		let p = StandardPolicy::new();
		let valid = key.with_policy(&p, None)?;

		// Process all valid user IDs
		for uid in valid.userids() {
			if let Ok(Some(email)) = uid.userid().email_normalized() {
				self.process_email(&email, &fp);
			}
		}

		// Merge with an existing key if present
		let key = match self.keys.remove(&fp) {
			Some(existing) => existing.merge_public_and_secret(key)?,
			None => key,
		};
		self.keys.insert(fp, key);
		Ok(())
	}

	/// Retrieves a certificate by fingerprint
	pub fn get(&self, fp: &Fingerprint) -> Option<&Cert> {
		self.keys.get(fp)
	}

	/// Finds a certificate by email components
	pub fn find_by_email(&self, encoded: &str, domain: &str) -> Option<(String, String, Cert)> {
		self.uids
			.iter()
			.find(|(components, _)| {
				components.encoded_local == encoded && components.domain == domain
			})
			.and_then(|(components, fp)| {
				self.get(fp).cloned().map(|cert| {
					(
						components.local_part.clone(),
						components.domain.clone(),
						cert,
					)
				})
			})
	}
}

/// Monitors a directory for PGP key files and maintains a key store
pub struct FileKeyProvider {
	// path is retained for internal use in the spawned task
	keys: Arc<RwLock<KeyStore>>,
	handle: JoinHandle<()>,
}

impl FileKeyProvider {
	/// Creates a new FileKeyProvider monitoring the specified directory
	pub fn new(path: PathBuf) -> Self {
		let mut keys = KeyStore::default();
		Self::load_directory(&mut keys, &path);

		let keys = Arc::new(RwLock::new(keys));
		let handle = Self::spawn_file_watcher(path, keys.clone());

		Self { keys, handle }
	}

	/// Loads all keys from a directory
	fn load_directory(keys: &mut KeyStore, path: &Path) {
		for file in path.read_dir().unwrap_or_else(|_| {
			tracing::error!("Failed to read directory: {}", path.display());
			std::fs::read_dir(path).unwrap() // Will panic if truly inaccessible
		}) {
			if let Ok(file) = file {
				let path = file.path();
				if let Err(err) = keys.load(&path) {
					tracing::error!("Failed to load key from {}: {}", path.display(), err);
				}
			}
		}
	}

	/// Spawns a file watcher task that monitors the directory for changes
	fn spawn_file_watcher(path: PathBuf, keys: Arc<RwLock<KeyStore>>) -> JoinHandle<()> {
		tokio::spawn(async move {
			let mut inotify = match Inotify::init() {
				Ok(i) => i,
				Err(e) => {
					tracing::error!("Error initializing inotify: {}", e);
					return;
				}
			};
			let mut buffer = [0; 1024];

			loop {
				if let Err(e) = inotify.watches().add(
					&path,
					WatchMask::CLOSE_WRITE | WatchMask::DELETE | WatchMask::MOVE,
				) {
					tracing::error!("Failed to add directory watch: {}", e);
					tokio::time::sleep(std::time::Duration::from_secs(5)).await;
					continue;
				}

				let mut es = match inotify.into_event_stream(&mut buffer) {
					Ok(s) => s,
					Err(e) => {
						tracing::error!("Error creating event stream: {}", e);
						break;
					}
				};

				while let Some(Ok(event)) = es.next().await {
					if let Some(name) = event.name {
						let file_path = path.join(name);
						let mut keys_guard = match keys.write() {
							Ok(guard) => guard,
							Err(e) => {
								tracing::error!("Failed to acquire write lock: {}", e);
								continue;
							}
						};

						if event
							.mask
							.intersects(EventMask::CLOSE_WRITE | EventMask::MOVED_TO)
						{
							if let Err(err) = keys_guard.load(&file_path) {
								tracing::error!("Failed to load key: {}", err);
							}
						} else if event
							.mask
							.intersects(EventMask::DELETE | EventMask::MOVED_FROM)
						{
							if let Err(err) = keys_guard.unload(&file_path) {
								tracing::error!("Failed to unload key: {}", err);
							}
						}
					}
				}
				inotify = es.into_inotify();
			}
		})
	}
}

impl Drop for FileKeyProvider {
	fn drop(&mut self) {
		self.handle.abort();
	}
}

/// Sanitizes a certificate to only include relevant data for a specific email
///
/// This function:
/// 1. Keeps only the UserID for the target email
/// 2. Removes any UserAttributes (photos, etc.)
/// 3. Retains only subkeys that can encrypt or sign
fn sanitize_cert(cert: Cert, target_email: &str) -> Cert {
	// 1. Keep only the one UserID we care about.
	let cert = cert.retain_userids(|ua| ua.userid().email().ok().flatten() == Some(target_email));
	// 2. Strip out any UserAttributes (e.g. photo packets).
	let cert = cert.retain_user_attributes(|_| false);
	// 3. Keep only subkeys that can encrypt or sign.
	cert.retain_subkeys(|sk| {
		// Look at the first self-signature's key flags.
		sk.self_signatures()
			.next()
			.and_then(|sig| sig.key_flags())
			.is_some_and(|flags| flags.for_transport_encryption() || flags.for_signing())
	})
}

impl KeyProvider for FileKeyProvider {
	fn discover<S: AsRef<str>>(&self, encoded: S, domain: S) -> Option<Cert> {
		let keys = self.keys.read().ok()?;
		keys.find_by_email(encoded.as_ref(), domain.as_ref())
			.map(|(local_part, domain, cert)| {
				sanitize_cert(cert, &format!("{local_part}@{domain}"))
			})
	}
}
