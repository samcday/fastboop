#[cfg(feature = "std")]
use std::path::Path;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(not(feature = "std"))]
use alloc::string::ToString;

#[cfg(not(feature = "std"))]
use alloc::vec;

use crate::dirent::DirEntry;
use crate::image::Image;
use crate::{EroFS, dirent::ReadDir};
use crate::{Error, Result, types::Inode};

/// An iterator for recursively walking a directory tree.
///
/// Created by [`EroFS::walk_dir`] or [`EroFS::read_dir`].
#[derive(Debug)]
pub struct WalkDir<'a, I: Image + Clone> {
    erofs: &'a EroFS<I>,
    dir_stack: Vec<(usize, ReadDir<'a, I>)>,
    max_depth: usize,
}

/// A single entry returned by [`WalkDir`].
pub struct WalkDirEntry {
    /// The depth of this entry relative to the starting directory (1-indexed).
    pub depth: usize,
    /// The directory entry containing file name and type.
    pub dir_entry: DirEntry,
    /// The inode containing file metadata.
    pub inode: Inode,
}

#[cfg(feature = "std")]
impl<'a, I: Image + Clone> WalkDir<'a, I> {
    pub(crate) fn new<P: AsRef<Path>>(erofs: &'a EroFS<I>, root: P) -> Result<Self> {
        let read_dir = {
            let inode = erofs
                .get_path_inode(&root)?
                .ok_or_else(|| Error::PathNotFound(root.as_ref().to_string_lossy().into_owned()))?;

            if !inode.file_type().is_dir() {
                return Err(Error::NotADirectory(
                    root.as_ref().to_string_lossy().into_owned(),
                ));
            }

            ReadDir::new(erofs, inode, root)?
        };
        Ok(WalkDir {
            erofs,
            dir_stack: vec![(1, read_dir)],
            max_depth: 0,
        })
    }

    /// Sets the maximum depth to descend into subdirectories.
    ///
    /// A depth of 1 means only immediate children are returned (like `read_dir`).
    /// A depth of 0 (the default) means unlimited depth.
    pub fn max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    fn get_walk_dir_entry(&mut self, dir_entry: DirEntry, depth: usize) -> Result<WalkDirEntry> {
        let inode = self.erofs.get_inode(dir_entry.nid())?;

        if (depth < self.max_depth || self.max_depth == 0) && dir_entry.file_type().is_dir() {
            let child_dir = ReadDir::new(self.erofs, inode, dir_entry.path())?;
            self.dir_stack.push((depth + 1, child_dir));
        }

        Ok(WalkDirEntry {
            depth,
            dir_entry,
            inode,
        })
    }

    fn next_entry(&mut self) -> Option<Result<WalkDirEntry>> {
        loop {
            let (depth, next_item) = {
                let (depth, dir) = self.dir_stack.last_mut()?;
                (*depth, dir.next())
            };

            match next_item {
                Some(Ok(entry)) => return Some(self.get_walk_dir_entry(entry, depth)),
                Some(Err(e)) => return Some(Err(e)),
                None => {
                    self.dir_stack.pop();
                }
            }
        }
    }
}

#[cfg(not(feature = "std"))]
impl<'a, I: Image + Clone> WalkDir<'a, I> {
    pub(crate) fn new<P: AsRef<str>>(erofs: &'a EroFS<I>, root: P) -> Result<Self> {
        let read_dir = {
            let inode = erofs
                .get_path_inode_str(root.as_ref())?
                .ok_or_else(|| Error::PathNotFound(root.as_ref().to_string()))?;

            if !inode.file_type().is_dir() {
                return Err(Error::NotADirectory(root.as_ref().to_string()));
            }

            ReadDir::new(erofs, inode, root)?
        };
        Ok(WalkDir {
            erofs,
            dir_stack: vec![(1, read_dir)],
            max_depth: 0,
        })
    }

    pub fn max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    fn get_walk_dir_entry(&mut self, dir_entry: DirEntry, depth: usize) -> Result<WalkDirEntry> {
        let inode = self.erofs.get_inode(dir_entry.nid())?;

        if (depth < self.max_depth || self.max_depth == 0) && dir_entry.file_type().is_dir() {
            let child_dir = ReadDir::new(self.erofs, inode, dir_entry.path())?;
            self.dir_stack.push((depth + 1, child_dir));
        }

        Ok(WalkDirEntry {
            depth,
            dir_entry,
            inode,
        })
    }

    fn next_entry(&mut self) -> Option<Result<WalkDirEntry>> {
        loop {
            let (depth, next_item) = {
                let (depth, dir) = self.dir_stack.last_mut()?;
                (*depth, dir.next())
            };

            match next_item {
                Some(Ok(entry)) => return Some(self.get_walk_dir_entry(entry, depth)),
                Some(Err(e)) => return Some(Err(e)),
                None => {
                    self.dir_stack.pop();
                }
            }
        }
    }
}

impl<I: Image + Clone> Iterator for WalkDir<'_, I> {
    type Item = Result<WalkDirEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_entry()
    }
}
