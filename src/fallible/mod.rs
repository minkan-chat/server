//! This module keeps the different result types. These are needed, because GraphQL does not have generics,
//! so we cannot build something like
//!
//! ```
//! struct<T, E> Result {
//!     ok: T,
//!     err: E,
//! }
//! ```
//!
//! Neither can we use enums with inner generics like [``std::result::Result``] does.
//!
//! We do it this way (instead of using [``async_graphql::Result``]) because these errors are not typed.
//! This errors are for operations that *can* fail because of things, the client does not know. For
//! example, then a client tries to register, it can't know if a username is available or not.

/// result_type macro
///
/// This macro generates a struct which can be used as a result to have typed errors in GraphQL.
/// It automatically derives [``async_graphql::SimpleObject``]. It will create a struct with two
/// fields: a field ``ok`` with an ``Option<$ok>`` on it and a field ``err`` with a ``Option<$err>``.
/// The intention is that on success, the ``ok`` field is Some($ok) and ``err`` is ``None``.
/// On failure, the ``ok`` field is None and the ``err`` field contains a ``Some($err)`` with the error.
///
/// # Example
///
/// ```rust
/// // This
/// result_type(SignupResult, String, String); // error shouldn't be a String in actual code
/// // will expand to
/// /*
/// pub struct SignupResult {
///     ok: String,
///     err: String,
/// }
/// */
///
/// // -- Default impl, From<$err> and new($ok) are generated too --
///
/// let some_result = SignupResult::new("That's okay!".to_string());
/// assert!(some_result.ok.is_some());
/// let value = some_result.ok.unwrap();
/// assert_eq!(value, "That's okay!".to_string());
/// ```
mod errors;

pub use errors::*;

#[macro_export]
macro_rules! result_type {
    (
        $name:ident,
        $ok:ty,
        $err:ty $(,)?
    ) => {
        #[derive(async_graphql::SimpleObject)]
        /// Result type
        /// Every result type is built the same way
        /// it has a field ``ok`` which has some value on success
        /// and the ``err`` field which is the ``Error`` interface.\
        /// The rule is: if there's an error, ``ok`` is null, ``err`` is some,
        /// if there is no error and the operation succeeds, ``err`` is none and
        /// ``ok`` is some.
        ///
        /// # Details
        ///
        /// We use this way instead of the ``errors`` field defined by the graphql
        /// schema, because these errors are not typed. With our way, you know
        /// exactly which errors could occur and they all implement the ``Error``
        /// interface so you can always be future proof.
        ///
        /// We'd really like to have only a single ``Result`` type, but for that
        /// we would need a concept like generics. GraphQL, however, does not
        /// have generics (yet). A union of all possible types on ``ok`` would
        /// be pretty ugly too.\
        /// Usually, each query/mutation returning a xResult should specify which
        /// errors are common / expected to occur.
        pub struct $name {
            pub ok: Option<$ok>,
            pub err: Option<$err>,
        }

        impl Default for $name {
            fn default() -> Self {
                Self {
                    ok: Option::default(),
                    err: Option::default(),
                }
            }
        }

        #[allow(dead_code)]
        impl $name {
            pub fn new(value: $ok) -> Self {
                Self {
                    ok: Some(value),
                    err: None,
                }
            }
        }

        impl From<$ok> for $name {
            fn from(ok: $ok) -> Self {
                Self {
                    ok: Some(ok),
                    err: None,
                }
            }
        }

        impl From<$err> for $name {
            fn from(err: $err) -> Self {
                Self {
                    ok: None,
                    err: Some(err),
                }
            }
        }

        impl From<Result<$ok, $err>> for $name {
            fn from(val: Result<$ok, $err>) -> Self {
                Self::from($crate::tri!(val))
            }
        }
    };
    (
        $name:ident,
        $ok:ty $(,)?
    ) => {
        $crate::result_type!($name, $ok, $crate::fallible::Error);
    };
}

/// error type macro
///
/// This macro is used to avoid repeating error types.
///
/// **Note**: Be sure to register this type in the [``crate::fallible::Error``] interface too.
///
/// # Example
///
/// ```rust
/// error_type {
///     struct SomeError {
///         extra_field: String
///     }
/// }
/// ```
///
/// This has only the default fields
/// ```rust
/// error_type {
///     struct OtherError;
/// }
/// ```
#[macro_export]
macro_rules! error_type {
    (
        $(#[$attr:meta])*
        struct $name:ident {
            $(
                $(#[$inner_attr:meta])*
                $field:ident: $field_type:ty,
            )*
        } $(,)?
    ) => {
        $(#[$attr])*
        #[derive(async_graphql::SimpleObject, Debug)]
        pub struct $name {

            pub description: String,
            pub hint: Option<String>,
            $(
                $(#[$inner_attr])*
                pub $field: $field_type,
            )*
        }

        impl $name {
            #[allow(unused)]
            pub fn new (description: String, $($field: $field_type),*) -> Self {
                Self {
                    description,
                    hint: None,
                    $($field),*
                }
            }
        }
    };
    (
        $(#[$attr:meta])*
        struct $name:ident$(;)?
    ) => {
        $crate::error_type!($(#[$attr])* struct $name {});
    };

    (
        $(#[$attr:meta])*
        $name:ident
    ) => {
        crate::error_type!(
            $(#[$attr])*
            struct $name
        );
    };
}

/// try_return
///
/// basically a copy of the ``try!`` macro, because we can't use ``?`` for early return
#[macro_export]
macro_rules! tri {
    (
        $expr:expr $(,)?
    ) => {
        match $expr {
            Ok(val) => val,
            Err(err) => return err.into(),
        }
    };
}
