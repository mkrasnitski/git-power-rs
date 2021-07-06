use anyhow::{Error, Result};
use git2::{ObjectType, Oid, Repository, ResetType};
use sha1::{Digest, Sha1};
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};

const NONCE_LENGTH: usize = 32;

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
        let start = match buf.find("-----BEGIN PGP SIGNATURE-----") {
            Some(pgp_idx) => match buf[pgp_idx..].find("Nonce") {
                Some(idx) => pgp_idx + idx + 7,
                None => {
                    let pgp_header_end = pgp_idx
                        + buf[pgp_idx..]
                            .find("\n ")
                            .ok_or("Malformed PGP header")
                            .map_err(Error::msg)?;
                    buf.insert_str(pgp_header_end, "\nNonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
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
                        buf.insert_str(header_end, "\nnonce AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
                        header_end + 7
                    }
                }
            }
        };
        let line_end = start
            + buf[start..]
                .find("\n")
                .ok_or("Malformed Nonce")
                .map_err(Error::msg)?;
        if line_end - start != NONCE_LENGTH {
            buf.replace_range(start..line_end, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        }
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
        // Only covers 128/160 bits of entropy
        // possible chars: ABCDEFGHIJKLMNOP
        let mut nonce_bytes = [b'A'; NONCE_LENGTH];
        for i in 0..NONCE_LENGTH {
            let idx = (val >> (4 * i)) & 0xF;
            nonce_bytes[31 - i] = b'A' + idx as u8;
        }
        // SAFETY: The nonce is always valid ASCII
        unsafe { self.buf[self.nonce_start..self.nonce_end].as_bytes_mut() }
            .copy_from_slice(&nonce_bytes);
    }

    fn bytes(&self) -> &[u8] {
        self.buf[self.header_len..].as_bytes()
    }
}

impl fmt::Display for CommitBuffer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self.buf[self.header_len..])
    }
}

fn num_leading_zero_bits(oid: &Oid) -> u32 {
    let mut zeros = 0;
    for &byte in oid.as_bytes() {
        zeros += byte.leading_zeros();
        if byte != 0 {
            break;
        }
    }
    zeros
}

fn try_commit(commit: CommitBuffer, target_zeros: u32) -> Result<(CommitBuffer, Oid)> {
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let num_hashes = Arc::new(AtomicU64::new(0));

    let n = num_cpus::get() as u128;
    let chunk_size = u128::MAX / n;
    for i in 0..n {
        let tx = tx.clone();
        let stop = Arc::clone(&stop);
        let num_hashes = Arc::clone(&num_hashes);
        let mut commit = commit.clone();
        std::thread::spawn(move || -> Result<()> {
            let mut hasher = Sha1::new();
            for nonce in i * chunk_size..(i + 1) * chunk_size {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                num_hashes.fetch_add(1, Ordering::Relaxed);
                commit.write_nonce(nonce);
                hasher.update(&commit.buf);
                let hash = Oid::from_bytes(hasher.finalize_reset().as_slice())?;
                let zeros = num_leading_zero_bits(&hash);
                if zeros >= target_zeros {
                    println!("{}", nonce);
                    tx.send(commit)?;
                    break;
                }
            }
            Ok(())
        });
    }
    let buf = rx.recv()?;
    stop.store(true, Ordering::Relaxed);

    let hash = Oid::hash_object(ObjectType::Commit, buf.bytes())?;
    println!(
        "{} {}",
        num_hashes.load(Ordering::Relaxed),
        num_leading_zero_bits(&hash)
    );
    println!("{}", buf);
    Ok((buf, hash))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        return Err(Error::msg(format!("Usage: {} [num-zeros]", args[0])));
    }
    let repo = Repository::open(std::env::current_dir()?)?;
    let head_commit_hash = repo.head()?.peel_to_commit()?.id();
    let odb = repo.odb()?;
    let buf = CommitBuffer::new(odb.read(head_commit_hash)?.data())?;

    let target_zeros = args[1].parse()?;
    let (buf, hash) = try_commit(buf, target_zeros)?;
    odb.write(ObjectType::Commit, buf.bytes())?;
    repo.reset(&repo.find_object(hash, None)?, ResetType::Soft, None)?;
    println!("found {}", hash);
    Ok(())
}
