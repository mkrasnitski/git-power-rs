# `git-power-rs`

## What is this?
Make your git tree into a blockchain! Inspired by [this project](https://github.com/CouleeApps/git-power), I noticed that there was a call to Rewrite it in Rust™, so I decided to tackle it as a way to learn about multithreading in Rust. More details on the What and Why can be found in the above repo.

## How fast does it go?
On my Ryzen 3600 @ 3.6 GHz with 12 threads, it achieves 35 MH/s peak, with this figure decreasing for longer commit messages (this includes signed commits). So, if you want to set the leading 8 digits of your commit to 0, that's 2^32 / 35000000 ~= 2 minutes, though variance is pretty high depending on the commit in question.

## Building
Just run `cargo build`.

## Installing
Run `cargo install --path .`, and the binary will be copied to `$CARGO_HOME/bin`. Make sure you have this directory in your `$PATH`, at which point you'll be able to invoke it through git itself via `git power`.

## Usage

    git power <bits>

This will brute-force the HEAD commit of the repository located in the current directory, and will use all available logical cores to perform the computation. If you want to apply this to multiple commits at a time, and not just the most recent one, perform an interactive rebase like so:

    git rebase --interactive --exec "git power" <ref>

The reference you give can be any git object, for example `--root`, `origin/master`, or a specific commit hash.

## Possible Further Optimization
 * Improve SHA-1 caching - Based on [prior work](https://github.com/CouleeApps/git-power/issues/1), it seems that there is space for optimizing the SHA-1 state to prevent redundant computation.
 * Use OpenCL to run it on GPUs - According to hashcat, my Radeon 5700XT is capable of a hashrate several hundred times higher than what I'm currently achieving just on my CPU.

 Feedback is appreciated for any other possible optimization improvements.
