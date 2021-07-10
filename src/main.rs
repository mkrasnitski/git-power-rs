use anyhow::{Error, Result};
use git2::{ObjectType, Oid, Repository, ResetType};
use sha1::{Digest, Sha1};
use std::convert::TryInto;
use std::fmt;
use std::io::{stdout, Write};
use std::sync::atomic::*;
use std::sync::{mpsc, Arc};
use std::time::Instant;
use structopt::StructOpt;

const NONCE_LENGTH: usize = 32;

#[derive(StructOpt)]
struct Config {
    #[structopt(short, long, default_value = "32")]
    bits: u16,

    #[structopt(short, long)]
    threads: Option<u8>,
}

#[derive(Clone)]
struct CommitBuffer {
    buf: String,
    header_len: usize,
    nonce_start: usize,
    nonce_end: usize,
}

impl CommitBuffer {
    fn new(buf: &[u8]) -> Result<Self> {
        let mut buf = String::from_utf8(buf.iter().cloned().collect())?;

        // The nonce will be in different locations depending on whether the commit is signed.
        //  - If it isn't, then we add the nonce as an additional field in the commit details,
        //    after the committer date.
        //  - If the commit is signed, then we add the Nonce as a header *inside* the GPG sig.
        //    Since the signature is only on the commit contents, the commit will stay signed.
        //    Any proper GPG client will ignore this header and verify the signature just fine.
        let start = match buf.find("-----BEGIN PGP SIGNATURE-----") {
            Some(pgp_idx) => match buf[pgp_idx..].find("Nonce") {
                Some(idx) => pgp_idx + idx + 7,
                None => {
                    let pgp_header_end = pgp_idx
                        + buf[pgp_idx..]
                            .find("\n ")
                            .ok_or("Malformed PGP header")
                            .map_err(Error::msg)?;
                    buf.insert_str(pgp_header_end, "\nNonce: ");
                    pgp_header_end + 8
                }
            },
            None => {
                let header_end = buf
                    .find("\n\n")
                    .ok_or("Malformed commit")
                    .map_err(Error::msg)?;
                match buf.find("nonce") {
                    Some(idx) => idx + 6,
                    None => {
                        buf.insert_str(header_end, "\nnonce ");
                        header_end + 7
                    }
                }
            }
        };

        // Here we insert the initial value of the nonce. In case the nonce already exists
        // and is shorter than the one we're inserting, we do a `replace_range`.
        let line_end = start
            + buf[start..]
                .find("\n")
                .ok_or("Malformed Nonce")
                .map_err(Error::msg)?;
        if line_end - start != NONCE_LENGTH {
            buf.replace_range(start..line_end, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        }

        // When git hashes an object, it prepends a header to the data which inclues the type
        // of the object, as well as its size. We opt to call out to a faster SHA-1 library,
        // so we need to prepend the header ourselves.
        let commit_header = format!("commit {}\0", buf.len());
        buf.insert_str(0, &commit_header);
        let header_len = commit_header.len();
        Ok(Self {
            buf,
            header_len,
            nonce_start: start + header_len,
            nonce_end: start + NONCE_LENGTH + header_len,
        })
    }

    fn write_nonce(&mut self, val: u128) {
        // Only covers 128/160 bits of entropy. Possible chars: ABCDEFGHIJKLMNOP
        let mut nonce_bytes = [b'A'; NONCE_LENGTH];
        for i in 0..NONCE_LENGTH {
            let idx = (val >> (4 * i)) & 0xF;
            nonce_bytes[31 - i] = b'A' + idx as u8;
        }
        // SAFETY: The nonce is always valid ASCII, and contain no multi-byte codepoints
        unsafe { self.buf[self.nonce_start..self.nonce_end].as_bytes_mut() }
            .copy_from_slice(&nonce_bytes);
    }

    fn data(&self) -> &str {
        // We just want the commit data itself, minus the prepended metadata header
        &self.buf[self.header_len..]
    }
}

impl fmt::Display for CommitBuffer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.data())
    }
}

enum PowMessage {
    Update([u8; 20], u16),
    Done(CommitBuffer, [u8; 20]),
}

fn num_leading_zero_bits(hash: &[u8]) -> u16 {
    let mut zeros = 0;
    for &byte in hash.iter() {
        zeros += byte.leading_zeros();
        if byte != 0 {
            break;
        }
    }
    zeros as u16
}

fn run_pow(commit: CommitBuffer, config: &Config) -> Result<(CommitBuffer, Oid)> {
    let start_time = Instant::now();
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let num_hashes = Arc::new(AtomicU64::new(0));
    let max_zeros = Arc::new(AtomicU16::new(0));
    let target_zeros = config.bits;

    // We divide the range of possible nonces evenly among each thread. Each thread loops
    // through each nonce in its given range and calculates a hash, and if it satisfies the
    // POW requirement, sends it to the main thread. When this happens, we stop all other
    // threads using the AtomicBool `stop`.
    let num_threads = config.threads.unwrap_or(num_cpus::get() as u8) as u128;
    let chunk_size = u128::MAX / num_threads;
    for i in 0..num_threads {
        let tx = tx.clone();
        let stop = Arc::clone(&stop);
        let num_hashes = Arc::clone(&num_hashes);
        let max_zeros = Arc::clone(&max_zeros);
        let mut commit = commit.clone();
        std::thread::spawn(move || -> Result<()> {
            // Since the part of the commit before the nonce never changes,
            // we reuse the SHA-1 state computed up to the nonce's location.
            let mut hasher = Sha1::new();
            hasher.update(&commit.buf[..commit.nonce_start]);
            for nonce in i * chunk_size..(i + 1) * chunk_size {
                // Check if a hash was already found by another thread
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                num_hashes.fetch_add(1, Ordering::Relaxed);

                // Write the nonce to the commit buffer and hash the buffer
                commit.write_nonce(nonce);
                let mut hasher = hasher.clone();
                hasher.update(&commit.buf[commit.nonce_start..]);
                let hash: [u8; 20] = hasher.finalize().as_slice().try_into()?;

                // Check against our win condition
                let num_zeros = num_leading_zero_bits(&hash);
                if num_zeros > max_zeros.load(Ordering::Relaxed) {
                    tx.send(PowMessage::Update(hash, num_zeros))?;
                    max_zeros.store(num_zeros, Ordering::Relaxed);
                }
                if num_zeros >= target_zeros {
                    tx.send(PowMessage::Done(commit, hash))?;
                    break;
                }
            }
            Ok(())
        });
    }
    let mut stdout = stdout();
    loop {
        match rx.recv()? {
            PowMessage::Update(hash, num_zeros) => {
                let hash = Oid::from_bytes(&hash)?;
                print!(
                    "\rFound {} ({}/{} leading zeros)",
                    hash, num_zeros, config.bits
                );
                stdout.flush().unwrap();
            }
            PowMessage::Done(buf, hash) => {
                stop.store(true, Ordering::Relaxed);
                // Print out some statistics once we're done
                let num_hashes = num_hashes.load(Ordering::Relaxed);
                let num_seconds =
                    Instant::now().duration_since(start_time).as_millis() as f64 / 1000.0;
                println!(
                    "\n{} attempts / {} seconds = {:.3}MH/s",
                    num_hashes,
                    num_seconds,
                    num_hashes as f64 / 1_000_000.0 / num_seconds as f64
                );
                let hash = Oid::from_bytes(&hash)?;
                return Ok((buf, hash));
            }
        }
    }
}

fn main() -> Result<()> {
    let config = Config::from_args();
    let repo = Repository::open(std::env::current_dir()?)?;
    let head_commit_hash = repo.head()?.peel_to_commit()?.id();
    let odb = repo.odb()?;
    let buf = CommitBuffer::new(odb.read(head_commit_hash)?.data())?;

    // Find the hash we're looking for, then commit the buffer to the git object db,
    // and finally soft reset to point HEAD to the new commit.
    let (buf, hash) = run_pow(buf, &config)?;
    odb.write(ObjectType::Commit, buf.data().as_bytes())?;
    repo.reset(&repo.find_object(hash, None)?, ResetType::Soft, None)?;
    Ok(())
}
