use anyhow::{Error, Result};
use git2::{Buf, Commit, ObjectType, Oid, Repository, ResetType, Time};
use std::io::Write;
use std::ops::Deref;

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

fn timestamp_string(time: i64, offset: i32) -> String {
    let t = Time::new(time, offset);
    let offset = t.offset_minutes().abs();
    format!(
        "{} {}{:02}{:02}",
        t.seconds(),
        t.sign(),
        offset / 60,
        offset % 60
    )
}

struct CommitBufferStr<'repo> {
    repo: &'repo Repository,
    buf: String,
}

impl<'repo> CommitBufferStr<'repo> {
    fn new(repo: &'repo Repository, b: Buf) -> Result<Self> {
        Ok(Self {
            repo,
            buf: b.as_str().valid_utf8()?.to_owned(),
        })
    }

    fn author_timestamp(&mut self) -> &mut [u8] {
        let start = self.buf.find('>').unwrap() + 2;
        let end = start + self.buf[start..].find('\n').unwrap();
        // SAFETY: The timestamp will always be valid UTF-8
        unsafe { self.buf[start..end].as_bytes_mut() }
    }

    fn set_author_timestamp(&mut self, time: i64, offset: i32) {
        self.author_timestamp()
            .copy_from_slice(timestamp_string(time, offset).as_bytes());
    }

    fn committer_timestamp(&mut self) -> &mut [u8] {
        let start = self.buf.find('>').unwrap() + 2;
        let start = start + self.buf[start..].find('>').unwrap() + 2;
        let end = start + self.buf[start..].find('\n').unwrap();
        // SAFETY: The timestamp will always be valid UTF-8
        unsafe { self.buf[start..end].as_bytes_mut() }
    }

    fn set_committer_timestamp(&mut self, time: i64, offset: i32) {
        self.committer_timestamp()
            .copy_from_slice(timestamp_string(time, offset).as_bytes());
    }

    fn write_to_odb(&self) -> Result<()> {
        let odb = self.repo.odb()?;
        let mut writer = odb.writer(self.buf.len(), ObjectType::Commit)?;
        writer.write(&self.buf.as_bytes())?;
        writer.finalize()?;
        Ok(())
    }
}

impl Deref for CommitBufferStr<'_> {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.buf
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
    let mut buf = CommitBufferStr::new(
        &repo,
        repo.commit_create_buffer(
            &author,
            &committer,
            &c.message().valid_utf8()?,
            &c.tree()?,
            c.parents()
                .collect::<Vec<Commit>>()
                .iter()
                .collect::<Vec<&Commit>>()
                .as_slice(),
        )?,
    )?;

    let mut author_offset_idx = 0;
    let mut committer_offset_idx = 0;
    let author_ts = author.when().seconds();
    let mut committer_ts = author_ts;

    let mut num_hashes = 0;
    loop {
        buf.set_author_timestamp(author_ts, TZ_OFFSETS[author_offset_idx]);
        buf.set_committer_timestamp(committer_ts, TZ_OFFSETS[committer_offset_idx]);
        let hash = Oid::hash_object(ObjectType::Commit, buf.as_bytes())?;
        let zeros = num_leading_zero_bits(&hash);
        if zeros >= target_zeros {
            println!("{} {}", num_hashes, zeros);
            println!("{}", &*buf);
            buf.write_to_odb()?;
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
            committer_ts += 1;
        }
    }
}

fn main() -> Result<()> {
    let repo = Repository::open(std::env::current_dir()?)?;
    let head_commit = repo.head()?.peel_to_commit()?;
    let hash = try_commit(&repo, &head_commit, 24)?;
    println!("found {}", hash);
    Ok(())
}
