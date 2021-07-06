use anyhow::Result;
use git2::{Commit, ObjectType, Oid, Repository, ResetType};

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

fn try_commit(repo: &Repository, c: &Commit, target_zeros: u32) -> Result<Oid> {
    if num_leading_zero_bits(&c.id()) >= target_zeros {
        return Ok(c.id());
    }

    let odb = repo.odb()?;
    let mut buf = String::from_utf8(odb.read(c.id())?.data().iter().copied().collect())?;

    let mut nonce = 0;
    let nonce_start = match buf.find("-----BEGIN PGP SIGNATURE-----") {
        Some(pgp_idx) => match buf.find("Nonce") {
            Some(idx) => idx + 7,
            None => {
                let pgp_header_end = pgp_idx + buf[pgp_idx..].find("\n ").unwrap();
                buf.insert_str(pgp_header_end, "\nNonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
                pgp_header_end + 8
            }
        },
        None => match buf.find("nonce") {
            Some(idx) => idx + 6,
            None => {
                let header_end = buf.find("\n\n").unwrap();
                buf.insert_str(header_end, "\nnonce AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
                header_end + 7
            }
        },
    };

    loop {
        let nonce_end = nonce_start + buf[nonce_start..].find("\n").unwrap();
        buf.replace_range(nonce_start..nonce_end, &nonce_string(nonce));
        let hash = Oid::hash_object(ObjectType::Commit, buf.as_bytes())?;
        let zeros = num_leading_zero_bits(&hash);
        if zeros >= target_zeros {
            println!("{} {}", nonce, zeros);
            println!("{}", buf);
            odb.write(ObjectType::Commit, &buf.as_bytes())?;
            let object = repo.find_object(hash, None)?;
            repo.reset(&object, ResetType::Soft, None)?;
            return Ok(hash);
        }

        nonce += 1;
    }
}

fn main() -> Result<()> {
    let repo = Repository::open(std::env::current_dir()?)?;
    let head_commit = repo.head()?.peel_to_commit()?;
    let hash = try_commit(&repo, &head_commit, 24)?;
    println!("found {}", hash);
    Ok(())
}
