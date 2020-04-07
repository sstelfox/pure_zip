# Pure Zip

A pure rust implementation for reading ZIP archives. This is a work in progress
for now. I needed a Zip library in Rust and the most active library on crates
right now isn't maintained and isn't compatible with the archives I've been
receiving.

Initial goals are to being able to reliably read all the Zip files I have. Once
it seems to be stable and well covered for reading I'll add writing of archives
as well, most of the primitives will already be there for it.

I'm currently not taking contributions and don't recommend either using this
for a reference or in your codebase until I have something stabilized.
