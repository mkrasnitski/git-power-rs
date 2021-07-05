use anyhow::{Error, Result};
use git2::{Commit, ObjectType, Oid, Repository, ResetType, Signature, Time};

const TZ_OFFSETS: [i32; 38] = [
    -720, -660, -600, -570, -540, -480, -420, -360, -300, -240, -210, -180, -120, -60, 0, 60, 120,
    180, 210, 240, 270, 300, 330, 345, 360, 390, 420, 480, 525, 540, 570, 600, 630, 660, 720, 765,
    780, 840,
];

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

fn try_commit(repo: &Repository, c: &Commit, target_zeros: u32) -> Result<Oid> {
    let author = c.author();
    let committer = c.committer();
    let message = c.message().valid_utf8()?;
    let tree = c.tree()?;
    let parents = c.parents().collect::<Vec<Commit>>();

    let mut author_offset_idx = 0;
    let mut committer_offset_idx = 0;
    let author_timestamp = author.when().seconds();
    let mut committer_timestamp = committer.when().seconds();
    println!("initial timestamp: {}", author_timestamp);

    let mut num_hashes = 0;
    loop {
        let author_sig = Signature::new(
            author.name().valid_utf8()?,
            author.email().valid_utf8()?,
            &Time::new(author_timestamp, TZ_OFFSETS[author_offset_idx]),
        )?;
        let committer_sig = Signature::new(
            committer.name().valid_utf8()?,
            committer.email().valid_utf8()?,
            &Time::new(committer_timestamp, TZ_OFFSETS[committer_offset_idx]),
        )?;
        let buf = repo.commit_create_buffer(
            &author_sig,
            &committer_sig,
            &message,
            &tree,
            parents.iter().collect::<Vec<&Commit>>().as_slice(),
        )?;
        let hash = Oid::hash_object(ObjectType::Commit, &buf)?;
        let zeros = num_leading_zero_bits(&hash);
        if zeros >= target_zeros {
            println!("{} {}", num_hashes, zeros);
            println!("{}", buf.as_str().valid_utf8()?);
            repo.commit(
                None,
                &author_sig,
                &committer_sig,
                &message,
                &tree,
                parents.iter().collect::<Vec<&Commit>>().as_slice(),
            )?;
            let object = repo.find_object(hash, None)?;
            repo.reset(&object, ResetType::Soft, None)?;
            return Ok(hash);
        }

        author_offset_idx += 1;
        num_hashes += 1;
        if author_offset_idx == TZ_OFFSETS.len() {
            author_offset_idx = 0;
            committer_offset_idx += 1;
        }
        if committer_offset_idx == TZ_OFFSETS.len() {
            committer_offset_idx = 0;
            committer_timestamp += 1;
        }
    }
}

fn main() -> Result<()> {
    let repo = Repository::open(std::env::current_dir()?)?;
    let head_commit = repo.head()?.peel_to_commit()?;
    let hash = try_commit(&repo, &head_commit, 16)?;
    println!("found {}", hash);
    Ok(())
}
