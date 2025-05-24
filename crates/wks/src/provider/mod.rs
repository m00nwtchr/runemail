use std::{
	collections::HashMap,
	path::{Path, PathBuf},
	sync::{Arc, RwLock},
};

use enum_dispatch::enum_dispatch;
use inotify::{EventMask, Inotify, WatchMask};
use sequoia_openpgp::{
	Cert, Fingerprint,
	armor::{Kind, Reader, ReaderMode},
	cert::ValidCert,
	packet::{Key, UserID},
	parse::Parse,
	policy::StandardPolicy,
	types::HashAlgorithm,
};
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;

#[enum_dispatch]
pub trait KeyProvider {
	fn discover<S: AsRef<str>>(&self, hashed: S, domain: S) -> Option<Cert>;
}

#[enum_dispatch(KeyProvider)]
pub enum KeyProviderType {
	FileKeyProvider(FileKeyProvider),
}

#[derive(Default)]
pub struct KeyStore {
	keys: HashMap<Fingerprint, Cert>,
	uids: HashMap<(String, String, String), Fingerprint>,
	files: HashMap<PathBuf, Fingerprint>,
}

/// Returns a 32 characters string from the local part of an email address
///
/// From [draft-koch]:
///     The so mapped local-part is hashed using the SHA-1 algorithm. The
///     resulting 160 bit digest is encoded using the Z-Base-32 method as
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
	pub fn load<P: AsRef<Path>>(&mut self, path: P) -> Result<(), Box<dyn std::error::Error>> {
		// let r = Reader::from_file(&path, ReaderMode::Tolerant(Some(Kind::PublicKey)))?;
		// let cert = Cert::from_buffered_reader(r)?;
		let cert = Cert::from_file(&path)?;
		let fp = cert.fingerprint();
		self.import(cert)?;
		self.files.insert(path.as_ref().to_path_buf(), fp);
		Ok(())
	}

	pub fn unload<P: AsRef<Path>>(&mut self, path: P) -> Result<Cert, Box<dyn std::error::Error>> {
		let fp = self
			.files
			.remove(&path.as_ref().to_path_buf())
			.ok_or("File not found")?;
		self.delete(&fp)
	}

	pub fn delete(&mut self, fp: &Fingerprint) -> Result<Cert, Box<dyn std::error::Error>> {
		let key = self.keys.remove(fp).ok_or("Key not found")?;
		self.uids.retain(|_, v| v != fp);
		Ok(key)
	}

	pub fn import(&mut self, key: Cert) -> Result<(), Box<dyn std::error::Error>> {
		let key = key.strip_secret_key_material();
		let fp = key.fingerprint();

		let p = StandardPolicy::new();
		let valid = key.with_policy(&p, None)?;

		for uid in valid.userids() {
			if let Ok(Some(email)) = uid.userid().email_normalized() {
				if let Some((local_part, domain)) = email.split_once('@') {
					self.uids.insert(
						(
							encode_local_part(local_part),
							local_part.to_string(),
							domain.to_string(),
						),
						fp.clone(),
					);
				}
			}
		}

		let key = match self.keys.remove(&fp) {
			Some(existing) => existing.merge_public_and_secret(key)?,
			None => key,
		};
		self.keys.insert(fp, key);

		Ok(())
	}

	pub fn get(&self, fp: &Fingerprint) -> Option<&Cert> {
		self.keys.get(fp)
	}
}

pub struct FileKeyProvider {
	path: PathBuf,

	keys: Arc<RwLock<KeyStore>>,
	handle: JoinHandle<()>,
}

impl FileKeyProvider {
	pub fn new(path: PathBuf) -> Self {
		let mut keys = KeyStore::default();

		for file in path.read_dir().unwrap() {
			let file = file.unwrap();
			let path = file.path();
			if let Err(err) = keys.load(path) {
				tracing::error!("Failed to load key: {}", err);
			}
		}

		let keys = Arc::new(RwLock::new(keys));
		let handle = tokio::spawn({
			let path = path.clone();
			let keys = keys.clone();
			async move {
				let mut inotify =
					Inotify::init().expect("Error while initializing inotify instance");
				let mut buffer = [0; 1024];

				loop {
					inotify
						.watches()
						.add(
							&path,
							WatchMask::CLOSE_WRITE | WatchMask::DELETE | WatchMask::MOVE,
						)
						.expect("Failed to add directory watch");

					let mut es = inotify.into_event_stream(&mut buffer).expect("");
					while let Some(Ok(event)) = es.next().await {
						if let Some(name) = event.name {
							let path = path.join(name);
							let mut keys = keys.write().unwrap();
							if event
								.mask
								.intersects(EventMask::CLOSE_WRITE | EventMask::MOVED_TO)
							{
								if let Err(err) = keys.load(path) {
									tracing::error!("Failed to load key: {}", err);
								}
							} else if event
								.mask
								.intersects(EventMask::DELETE | EventMask::MOVED_FROM)
							{
								if let Err(err) = keys.unload(path) {
									tracing::error!("Failed to unload key: {}", err);
								}
							}
						}
					}
					inotify = es.into_inotify();
				}
			}
		});

		Self { path, keys, handle }
	}
}

impl Drop for FileKeyProvider {
	fn drop(&mut self) {
		self.handle.abort();
	}
}

fn sanitize_cert(cert: Cert, target_email: &str) -> sequoia_openpgp::Result<Cert> {
	// 1. Keep only the one UserID we care about.
	let cert = cert
		.retain_userids(|ua| ua.userid().email().ok().flatten().as_deref() == Some(target_email));
	// 2. Strip out any UserAttributes (e.g. photo packets).
	let cert = cert.retain_user_attributes(|_| false);
	// 3. Keep only subkeys that can encrypt or sign.
	let cert = cert.retain_subkeys(|sk| {
		// Look at the first self-signature’s key flags.
		sk.self_signatures()
			.next()
			.and_then(|sig| sig.key_flags())
			.map_or(false, |flags| {
				flags.for_transport_encryption() || flags.for_signing()
			})
	});

	Ok(cert)
}

impl KeyProvider for FileKeyProvider {
	fn discover<S: AsRef<str>>(&self, encoded: S, domain: S) -> Option<Cert> {
		let keys = self.keys.read().unwrap();

		keys.uids
			.iter()
			.find(|((en, _, d), _)| en.eq(encoded.as_ref()) && d.eq(domain.as_ref()))
			.and_then(|((_, lp, d), fp)| {
				keys.get(fp)
					.cloned()
					.map(|cert| (lp.clone(), d.clone(), cert))
			})
			.and_then(|(local_part, domain, cert)| {
				sanitize_cert(cert, &format!("{}@{}", local_part, domain)).ok()
			})
	}
}
