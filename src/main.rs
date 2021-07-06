use anyhow::Result;
use git2::{ObjectType, Oid, Repository, ResetType};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};

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

fn nonce_bytes(nonce: u128) -> [u8; 32] {
    let mut nonce_bytes = [b'A'; 32];
    // only covers 128/160 bits of entropy
    // possible chars: ABCDEFGHIJKLMNOP
    for i in 0..32 {
        let idx = (nonce >> (4 * i)) & 0xF;
        nonce_bytes[31 - i] = b'A' + idx as u8;
    }
    nonce_bytes
}

fn write_nonce(buf: &mut String, start: usize, val: u128, first: &mut bool) {
    let nonce_bytes = nonce_bytes(val);
    let end = if *first {
        *first = false;
        start + buf[start..].find("\n").unwrap()
    } else {
        start + 32
    };
    if end - start != 32 {
        let nonce_string: String = nonce_bytes.iter().map(|c| *c as char).collect();
        buf.replace_range(start..end, &nonce_string);
    } else {
        // SAFETY: The nonce is always valid UTF-8
        unsafe { buf[start..end].as_bytes_mut() }.copy_from_slice(&nonce_bytes);
    }
}

fn try_commit(mut buf: String, target_zeros: u32) -> Result<(String, Oid)> {
    let start = match buf.find("-----BEGIN PGP SIGNATURE-----") {
        Some(pgp_idx) => match buf[pgp_idx..].find("Nonce") {
            Some(idx) => pgp_idx + idx + 7,
            None => {
                let pgp_header_end = pgp_idx + buf[pgp_idx..].find("\n ").unwrap();
                buf.insert_str(pgp_header_end, "\nNonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
                pgp_header_end + 8
            }
        },
        None => {
            let header_end = buf.find("\n\n").unwrap();
            match buf.find("nonce") {
                Some(idx) => idx + 6,
                None => {
                    buf.insert_str(header_end, "\nnonce AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
                    header_end + 7
                }
            }
        }
    };

    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let num_hashes = Arc::new(AtomicU64::new(0));

    let n = num_cpus::get() as u128;
    let chunk_size = u128::MAX / n;
    for i in 0..n {
        let tx = tx.clone();
        let stop = Arc::clone(&stop);
        let num_hashes = Arc::clone(&num_hashes);
        let mut buf = buf.clone();
        std::thread::spawn(move || {
            let mut first = true;
            for nonce in i * chunk_size..(i + 1) * chunk_size {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                num_hashes.fetch_add(1, Ordering::Relaxed);
                write_nonce(&mut buf, start, nonce, &mut first);
                let hash = Oid::hash_object(ObjectType::Commit, buf.as_bytes()).unwrap();
                let zeros = num_leading_zero_bits(&hash);
                if zeros >= target_zeros {
                    tx.send(buf).unwrap();
                    break;
                }
            }
        });
    }
    let buf = rx.recv()?;
    stop.store(true, Ordering::Relaxed);

    let hash = Oid::hash_object(ObjectType::Commit, buf.as_bytes())?;
    println!(
        "{} {}",
        num_hashes.load(Ordering::Relaxed),
        num_leading_zero_bits(&hash)
    );
    println!("{}", buf);
    Ok((buf, hash))
}

fn main() -> Result<()> {
    let repo = Repository::open(std::env::current_dir()?)?;
    let head_commit_hash = repo.head()?.peel_to_commit()?.id();
    let odb = repo.odb()?;
    let commit_data = odb.read(head_commit_hash)?.data().iter().cloned().collect();
    let buf = String::from_utf8(commit_data)?;

    let target_zeros = 28;
    let (buf, hash) = try_commit(buf.clone(), target_zeros)?;
    odb.write(ObjectType::Commit, buf.as_bytes())?;
    repo.reset(&repo.find_object(hash, None)?, ResetType::Soft, None)?;
    println!("found {}", hash);
    Ok(())
}
