use anyhow::{Error, Result};
use git2::{ObjectType, Oid, Repository, ResetType};
use rayon::prelude::*;

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

fn nonce_string(nonce: u128) -> String {
    let alphabet = "ABCDEFGHIJKLMNOP";
    let mut nonce_string = String::new();
    // only covers 128/160 bits of entropy
    for i in 0..32 {
        let idx = (nonce >> (4 * i)) & 0xF;
        nonce_string.insert(0, alphabet.chars().nth(idx as usize).unwrap());
    }
    nonce_string
}

fn write_nonce(buf: &mut String, start: usize, val: u128) {
    let end = start + buf[start..].find("\n").unwrap();
    buf.replace_range(start..end, &nonce_string(val));
}

fn try_commit(mut buf: String, target_zeros: u32) -> Result<(String, Oid)> {
    let nonce_start = match buf.find("-----BEGIN PGP SIGNATURE-----") {
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

    let good_nonce = (0..u128::MAX)
        .into_par_iter()
        .find_any(|&nonce| {
            let mut buf = buf.clone();
            write_nonce(&mut buf, nonce_start, nonce);
            let hash = Oid::hash_object(ObjectType::Commit, buf.as_bytes()).unwrap();
            let zeros = num_leading_zero_bits(&hash);
            zeros >= target_zeros
        })
        .ok_or("Hash not found")
        .map_err(Error::msg)?;

    write_nonce(&mut buf, nonce_start, good_nonce);
    let hash = Oid::hash_object(ObjectType::Commit, buf.as_bytes())?;
    println!("{} {}", good_nonce, num_leading_zero_bits(&hash));
    println!("{}", buf);
    Ok((buf, hash))
}

fn main() -> Result<()> {
    let repo = Repository::open(std::env::current_dir()?)?;
    let head_commit_hash = repo.head()?.peel_to_commit()?.id();
    let odb = repo.odb()?;
    let commit_data = odb.read(head_commit_hash)?.data().iter().cloned().collect();
    let buf = String::from_utf8(commit_data)?;

    let target_zeros = 24;
    let (buf, hash) = try_commit(buf.clone(), target_zeros)?;
    odb.write(ObjectType::Commit, buf.as_bytes())?;
    repo.reset(&repo.find_object(hash, None)?, ResetType::Soft, None)?;
    println!("found {}", hash);
    Ok(())
}
