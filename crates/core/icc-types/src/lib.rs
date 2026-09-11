#![no_std]
#![forbid(unsafe_code)]

//! Small, platform-neutral value types shared by Independent Computing Core.

macro_rules! opaque_id {
    ($name:ident, $size:expr) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; $size]);

        impl $name {
            pub const fn from_bytes(bytes: [u8; $size]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; $size] {
                &self.0
            }
        }
    };
}

opaque_id!(IdentityId, 16);
opaque_id!(AppId, 16);
opaque_id!(ObjectId, 16);
opaque_id!(SecurityStateKey, 32);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Generation(u64);

impl Generation {
    pub const ZERO: Self = Self(0);

    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct WallTimeMs(u64);

impl WallTimeMs {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct MonotonicMs(u64);

impl MonotonicMs {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretHandle(u64);

impl SecretHandle {
    pub const fn from_raw_for_adapter(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn raw_for_adapter(self) -> u64 {
        self.0
    }
}
