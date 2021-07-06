use anyhow::{Error, Result};
use git2::{Commit, ObjectType, Oid, Repository, ResetType};
use std::io::Write;

trait ValidUTF8<T> {
    fn valid_utf8(self) -> Result<T>
    where
        Self: Sized;
}

impl<'a> ValidUTF8<&'a str> for Option<&'a str> {
    fn valid_utf8(self) -> Result<&'a str> {
        self.ok_or("Invalid UTF-8").map_err(Error::msg)
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

fn nonce_string(nonce: u128) -> String {
    let alphabet = "ABCDEFGHIJKLMNOP";
    let mut nonce_string = String::new();
    for i in 0..40 {
        // prevents weird bitshift overflows, but only covers 128/160 bits of entropy
        let idx = if i < 32 { (nonce >> (4 * i)) & 0xF } else { 0 };
        nonce_string.insert(0, alphabet.chars().nth(idx as usize).unwrap());
    }
    nonce_string
}

fn try_commit(repo: &Repository, c: &Commit, target_zeros: u32) -> Result<Oid> {
    let author = c.author();
    let committer = c.committer();
    let mut buf = repo
        .commit_create_buffer(
            &author,
            &committer,
            &c.message().valid_utf8()?,
            &c.tree()?,
            c.parents()
                .collect::<Vec<Commit>>()
                .iter()
                .collect::<Vec<&Commit>>()
                .as_slice(),
        )?
        .as_str()
        .valid_utf8()?
        .to_owned();

    let mut nonce = 1;
    let nonce_idx = match buf.find("-----BEGIN PGP SIGNATURE-----") {
        Some(pgp_idx) => match buf.find("Nonce") {
            Some(idx) => idx + 7,
            None => {
                let pgp_header_end = pgp_idx + buf[pgp_idx..].find("\n").unwrap();
                buf.insert_str(
                    pgp_header_end,
                    "\nNonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                );
                pgp_header_end + 8
            }
        },
        None => match buf.find("nonce") {
            Some(idx) => idx + 6,
            None => {
                let header_end = buf.find("\n\n").unwrap();
                buf.insert_str(
                    header_end,
                    "\nnonce AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                );
                header_end + 7
            }
        },
    };

    loop {
        buf.replace_range(nonce_idx..nonce_idx + 40, &nonce_string(nonce));
        let hash = Oid::hash_object(ObjectType::Commit, buf.as_bytes())?;
        let zeros = num_leading_zero_bits(&hash);
        if zeros >= target_zeros {
            println!("{} {}", nonce, zeros);
            println!("{}", buf);

            let odb = repo.odb()?;
            let mut writer = odb.writer(buf.len(), ObjectType::Commit)?;
            writer.write(&buf.as_bytes())?;
            writer.finalize()?;

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
    let hash = try_commit(&repo, &head_commit, 20)?;
    println!("found {}", hash);
    Ok(())
}
