#![no_std]
#![forbid(unsafe_code)]

//! Explicit resource rights with monotonic attenuation.

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Rights(u32);

impl Rights {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const DELETE: Self = Self(1 << 2);
    pub const DELEGATE: Self = Self(1 << 3);

    pub const fn from_bits(bits: u32) -> Option<Self> {
        const KNOWN: u32 = Rights::READ.0 | Rights::WRITE.0 | Rights::DELETE.0 | Rights::DELEGATE.0;
        if bits & !KNOWN == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    pub const fn is_subset_of(self, parent: Self) -> bool {
        parent.contains(self)
    }

    pub const fn attenuate(self, requested: Self) -> Option<Self> {
        if requested.is_subset_of(self) {
            Some(requested)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Rights;

    #[test]
    fn attenuation_cannot_add_rights() {
        let parent = Rights::READ.union(Rights::DELEGATE);
        assert_eq!(parent.attenuate(Rights::READ), Some(Rights::READ));
        assert_eq!(parent.attenuate(Rights::WRITE), None);
    }
}
