//! Integer codes stored in SQLite columns, defined once here. Views expose the labels.
//! The numbers and labels are part of the contract: never renumber, only append.

/// Declares a `#[repr(u8)]` enum with its numeric code and label. Keeping the
/// variant list in one place means `code`, `from_code`, `label` and `ALL` cannot drift apart.
macro_rules! coded_enum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident = $code:literal => $label:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(u8)]
        pub enum $name { $($variant = $code),+ }

        impl $name {
            /// Every variant, for tests and for generating the SQL label views.
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            pub fn code(self) -> u8 {
                self as u8
            }

            /// `None` for a code this build does not know, so old or corrupt rows
            /// surface as a missing label instead of a panic.
            #[allow(dead_code)] // Tests only so far; Task 8 reads codes back.
            pub fn from_code(code: u8) -> Option<Self> {
                match code {
                    $($code => Some($name::$variant),)+
                    _ => None,
                }
            }

            pub fn label(self) -> &'static str {
                match self {
                    $($name::$variant => $label),+
                }
            }
        }
    };
}

coded_enum! {
    /// What the server did with a query.
    Outcome {
        Allowed = 0 => "allowed",
        Blocked = 1 => "blocked",
        Rewritten = 2 => "rewritten",
        Refused = 3 => "refused",
    }
}

coded_enum! {
    /// Why that outcome was chosen.
    Reason {
        None = 0 => "none",
        Rule = 1 => "rule",
        Cname = 2 => "cname",
        RefusedName = 3 => "refused_name",
        AnyQuery = 4 => "any_query",
    }
}

coded_enum! {
    /// Where an answer came from.
    ServedFrom {
        Cache = 0 => "cache",
        StaleCache = 1 => "stale_cache",
        Upstream = 2 => "upstream",
        Fallback = 3 => "fallback",
        Local = 4 => "local",
    }
}

coded_enum! {
    /// Which system wrote the row.
    Source {
        Sieve = 0 => "sieve",
        Adguard = 1 => "adguard",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trips every variant of one enum, and checks that the next code is unknown.
    macro_rules! round_trips {
        ($t:ident) => {{
            for &v in $t::ALL {
                assert_eq!($t::from_code(v.code()), Some(v));
            }
            assert_eq!($t::from_code($t::ALL.len() as u8), None);
        }};
    }

    #[test]
    fn codes_round_trip() {
        round_trips!(Outcome);
        round_trips!(Reason);
        round_trips!(ServedFrom);
        round_trips!(Source);
    }

    #[test]
    fn labels_match_contract() {
        assert_eq!(Outcome::Blocked.label(), "blocked");
        assert_eq!(ServedFrom::StaleCache.label(), "stale_cache");
        assert_eq!(Reason::RefusedName.label(), "refused_name");
        assert_eq!(Reason::AnyQuery.label(), "any_query");
        assert_eq!(Source::Adguard.label(), "adguard");
        assert_eq!(ServedFrom::Local.code(), 4);
    }
}
