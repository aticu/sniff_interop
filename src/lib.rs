/// Contains types to transfer data out of sniff.

use std::fmt;

/// Represents a change from one value to another.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Change<T> {
    /// The value before the change.
    pub from: T,
    /// The value after the change.
    pub to: T,
}

impl<T> Change<T> {
    /// Maps the contained values to a new value.
    fn map<R, F: FnMut(&T) -> R>(&self, mut f: F) -> Change<R> {
        Change {
            from: f(&self.from),
            to: f(&self.to),
        }
    }
}

impl<T: Ord> Change<T> {
    /// Compares the old value to the new value.
    pub fn cmp(&self) -> std::cmp::Ordering {
        self.from.cmp(&self.to)
    }
}

/// Represents a possibly changed value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum MaybeChange<T> {
    /// The value was changed.
    Change(Change<T>),
    /// The value was not changed.
    Same(T),
}

impl<T> MaybeChange<T> {
    /// Maps the contained values to a new value.
    fn map<R, F: FnMut(&T) -> R>(&self, mut f: F) -> MaybeChange<R> {
        match self {
            MaybeChange::Change(change) => MaybeChange::Change(change.map(f)),
            MaybeChange::Same(val) => MaybeChange::Same(f(val)),
        }
    }

    /// Returns whether a change occurred or not.
    pub fn is_changed(&self) -> bool {
        matches!(self, Self::Change(_))
    }

    /// Returns the new value after a possible change.
    pub fn new_val(&self) -> &T {
        match self {
            Self::Change(change) => &change.to,
            Self::Same(val) => val,
        }
    }

    /// Returns the old value before a possible change.
    pub fn old_val(&self) -> &T {
        match self {
            Self::Change(change) => &change.from,
            Self::Same(val) => val,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(into = "String", try_from = "&str")]
pub struct Hash(pub [u8; 32]);

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }

        Ok(())
    }
}

impl From<Hash> for String {
    fn from(value: Hash) -> Self {
        format!("{value:?}")
    }
}

impl TryFrom<&str> for Hash {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut bytes = [0; 32];
        hex::decode_to_slice(value, &mut bytes).map_err(|err| format!("{err}"))?;

        Ok(Hash(bytes))
    }
}

/// Represents a change of a file system entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum EntryDiff {
    /// The underlying file has changed.
    FileChanged {
        /// The change of the file hash represented as a string.
        hash_change: Change<Hash>,
    },
    /// The underlying symlink has changed.
    SymlinkChanged {
        /// The change of the path inside the symlink.
        path_change: Change<String>,
    },
    /// The type of the entry has changed.
    ///
    /// The contained strings will be a description of the involved types.
    TypeChange(Change<String>),
    /// Some other change occurred.
    OtherChange,
}

/// The types of named streams associated with a path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum NamedStreamType {
    /// The NTFS reparse data of a path.
    ReparseData,
    /// The NTFS access control list of a path.
    AccessControlList,
    /// The DOS name of a path.
    DosName,
    /// The object ID of a path.
    ObjectId,
    /// The encrypted file system info of a path.
    EncryptedFileSystemInfo,
    /// The extended attributes of a path.
    ExtendedAttributes,
    /// An alternate data stream associated with a path.
    AlternateDataStream {
        /// The name of the alternate data stream.
        name: String,
    },
}

/// The format description for timestamps.
const TIMESTAMP_FORMAT: &[time::format_description::FormatItem] = time::macros::format_description!(
    "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:1+]"
);

/// Serialization and deserialization of timestamps.
mod timestamp_serde {
    /// Serializes a timestamp as a string.
    pub(super) fn serialize<S>(
        timestamp: &time::OffsetDateTime,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let as_str = timestamp
            .format(super::TIMESTAMP_FORMAT)
            .map_err(<S::Error as serde::ser::Error>::custom)?;
        serializer.serialize_str(&as_str)
    }

    /// Parses a timestamp from a string in the deserializer.
    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<time::OffsetDateTime, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = time::OffsetDateTime;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str(
                    "a string representation of a date in `yyyy-mm-dd HH:MM:SS.ssss` format",
                )
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                time::PrimitiveDateTime::parse(v, super::TIMESTAMP_FORMAT)
                    .map_err(|err| E::custom(err))
                    .map(|time| time.assume_utc())
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

/// A timestamp.
#[derive(Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, PartialOrd, Ord)]
#[serde(transparent)]
pub struct Timestamp {
    /// The inner timestamp.
    #[serde(with = "timestamp_serde")]
    inner: time::OffsetDateTime,
}

impl std::ops::Deref for Timestamp {
    type Target = time::OffsetDateTime;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format(TIMESTAMP_FORMAT).unwrap())
    }
}

impl<T: Into<time::OffsetDateTime>> From<T> for Timestamp {
    fn from(value: T) -> Self {
        Timestamp {
            inner: value.into(),
        }
    }
}

/// Represents a single change in the metadata.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum MetadataChange {
    /// The size changed.
    Size(Change<u64>),
    /// The NFTS attributes changed.
    NtfsAttributes(Change<Option<u32>>),
    /// The unix permissions changed.
    UnixPermissions(Change<Option<u32>>),
    /// The number of links to the path changed.
    Nlink(Change<Option<u64>>),
    /// The user id changed.
    Uid(Change<Option<u32>>),
    /// The group id changed.
    Gid(Change<Option<u32>>),
    /// A named stream associated with the path changed.
    NamedStream(NamedStreamType, Change<Option<Vec<u8>>>),
}

/// The relevant information about the metadata and its changes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct MetadataInfo<Timestamp> {
    /// The changes in this diff.
    pub changes: Vec<MetadataChange>,
    /// The inode associated with the metadata.
    pub inode: MaybeChange<Option<u64>>,
    /// The timestamp of creation associated with the metadata.
    pub created: MaybeChange<Option<Timestamp>>,
    /// The timestamp of the last modification associated with the metadata.
    pub modified: MaybeChange<Option<Timestamp>>,
    /// The timestamp of the last access associated with the metadata.
    pub accessed: MaybeChange<Option<Timestamp>>,
    /// The timestamp of the last inode modification associated with the metadata.
    pub inode_modified: MaybeChange<Option<Timestamp>>,
}

impl<Timestamp> MetadataInfo<Timestamp> {
    /// Transforms the contained timestamps by applying the given function to it.
    fn transform_timestamps<NewTimestamp, F: FnMut(&Timestamp) -> NewTimestamp>(
        &self,
        mut f: F,
    ) -> MetadataInfo<NewTimestamp> {
        MetadataInfo {
            changes: self.changes.clone(),
            inode: self.inode.clone(),
            created: self.created.map(|ts_opt| ts_opt.as_ref().map(&mut f)),
            modified: self.modified.map(|ts_opt| ts_opt.as_ref().map(&mut f)),
            accessed: self.accessed.map(|ts_opt| ts_opt.as_ref().map(&mut f)),
            inode_modified: self
                .inode_modified
                .map(|ts_opt| ts_opt.as_ref().map(&mut f)),
        }
    }
}

/// Represents a change of a file system entry and its associated metadata.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum MetaEntryDiff<Timestamp> {
    /// The entry was added.
    Added(MetadataInfo<Timestamp>),
    /// The entry was deleted.
    Deleted(MetadataInfo<Timestamp>),
    /// Only the metadata changed.
    MetaOnlyChange(MetadataInfo<Timestamp>),
    /// The entry changed (and with it likely the metadata too).
    EntryChange(EntryDiff, MetadataInfo<Timestamp>),
}

impl<Timestamp> MetaEntryDiff<Timestamp> {
    /// Returns the enclosed metadata info.
    pub fn meta_info(&self) -> &MetadataInfo<Timestamp> {
        match self {
            MetaEntryDiff::Added(info)
            | MetaEntryDiff::Deleted(info)
            | MetaEntryDiff::EntryChange(_, info)
            | MetaEntryDiff::MetaOnlyChange(info) => info,
        }
    }

    /// Transforms the contained timestamps by applying the given function to it.
    pub fn transform_timestamps<NewTimestamp, F: FnMut(&Timestamp) -> NewTimestamp>(
        &self,
        f: F,
    ) -> MetaEntryDiff<NewTimestamp> {
        match self {
            MetaEntryDiff::Added(meta) => MetaEntryDiff::Added(meta.transform_timestamps(f)),
            MetaEntryDiff::Deleted(meta) => MetaEntryDiff::Deleted(meta.transform_timestamps(f)),
            MetaEntryDiff::MetaOnlyChange(meta) => {
                MetaEntryDiff::MetaOnlyChange(meta.transform_timestamps(f))
            }
            MetaEntryDiff::EntryChange(entry, meta) => {
                MetaEntryDiff::EntryChange(entry.clone(), meta.transform_timestamps(f))
            }
        }
    }
}

/// Represents a set of changes for a whole diff tree.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Changeset<Timestamp> {
    /// The earliest possible in this changeset.
    pub earliest_timestamp: self::Timestamp,
    /// All the changes in this change set.
    pub changes: std::collections::BTreeMap<String, MetaEntryDiff<Timestamp>>,
}

impl<Timestamp> Changeset<Timestamp> {
    /// Transforms the contained timestamps by applying the given function to it.
    pub fn transform_timestamps<NewTimestamp, F: FnMut(&Timestamp) -> NewTimestamp>(
        &self,
        mut f: F,
    ) -> Changeset<NewTimestamp> {
        Changeset {
            earliest_timestamp: self.earliest_timestamp.clone(),
            changes: self
                .changes
                .iter()
                .map(|(path, diff)| (path.clone(), diff.transform_timestamps(&mut f)))
                .collect(),
        }
    }
}
