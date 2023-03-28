#![allow(unused_macros)]

use std::collections::HashMap;
use std::convert::{From, TryFrom};
use std::fmt;
use std::ops::{Index, IndexMut};

use indexmap::IndexMap;
use serde_json::{json, Value as JsonValue};

use crate::error::{err, Error as CESRError, Result};

pub type Array = Vec<Value>;
pub type Object = IndexMap<String, Value>;

#[derive(Debug, PartialEq, Clone)]
pub struct Number {
    f: f64,
    i: i64,
    float: bool,
}

impl From<f64> for Number {
    fn from(f: f64) -> Self {
        Self { f, i: 0, float: true }
    }
}

impl From<i64> for Number {
    fn from(i: i64) -> Self {
        Self { f: 0.0, i, float: false }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum Value {
    Null,
    Boolean(bool),
    Number(Number),
    String(String),
    Array(Array),
    Object(Object),
}

impl Value {
    pub fn to_bool(&self) -> Result<bool> {
        match self {
            Self::Boolean(boolean) => Ok(*boolean),
            _ => err!(CESRError::Conversion("cannot convert to boolean".to_string())),
        }
    }

    #[allow(clippy::inherent_to_string_shadow_display)]
    pub fn to_string(&self) -> Result<String> {
        match self {
            Self::String(string) => Ok(string.clone()),
            _ => err!(CESRError::Conversion("cannot convert to string".to_string())),
        }
    }

    pub fn to_i64(&self) -> Result<i64> {
        match self {
            Self::Number(number) => {
                if number.float {
                    return err!(CESRError::Conversion(
                        "cannot convert float to integer".to_string()
                    ));
                }

                Ok(number.i)
            }
            _ => err!(CESRError::Conversion("cannot convert to integer".to_string())),
        }
    }

    pub fn to_f64(&self) -> Result<f64> {
        match self {
            Self::Number(number) => {
                if !number.float {
                    return err!(CESRError::Conversion(
                        "cannot convert integer to float".to_string()
                    ));
                }

                Ok(number.f)
            }
            _ => err!(CESRError::Conversion("cannot convert to float".to_string())),
        }
    }

    pub fn to_vec(&self) -> Result<Vec<Value>> {
        match self {
            Self::Array(array) => Ok(array.clone()),
            _ => err!(CESRError::Conversion("cannot convert to vec".to_string())),
        }
    }

    pub fn to_map(&self) -> Result<IndexMap<String, Value>> {
        match self {
            Self::Object(map) => Ok(map.clone()),
            _ => err!(CESRError::Conversion("cannot convert to map".to_string())),
        }
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(match self {
            Self::Null => "null".to_string(),
            Self::Boolean(b) => json!(b).to_string(),
            Self::Number(n) => {
                if n.float {
                    json!(n.f).to_string()
                } else {
                    json!(n.i).to_string()
                }
            }
            Self::String(s) => json!(s).to_string(),
            Self::Array(a) => {
                let mut v = Vec::new();
                for element in a {
                    v.push(element.to_json()?);
                }
                format!("[{}]", v.join(","))
            }
            Self::Object(o) => {
                let mut v = Vec::new();
                for (key, value) in o {
                    v.push(format!("{}:{}", json!(key), value.to_json()?));
                }
                format!("{{{}}}", v.join(","))
            }
        })
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let json = match self.to_json() {
            Ok(j) => j,
            // hopefully unreachable (.to_json() should never blow up)
            Err(_) => return Err(fmt::Error),
        };
        write!(f, "{json}")
    }
}

impl Index<usize> for Value {
    type Output = Value;
    fn index(&self, i: usize) -> &Self::Output {
        match self {
            Value::Array(a) => &a[i],
            Value::Object(o) => &o[i],
            _ => panic!("attempted to index non-indexable Value object with usize"),
        }
    }
}

impl Index<&str> for Value {
    type Output = Value;
    fn index(&self, i: &str) -> &Self::Output {
        match self {
            Value::Object(o) => &o[i],
            _ => panic!("attempted to index non-indexable Value object with string"),
        }
    }
}

impl IndexMut<usize> for Value {
    fn index_mut(&mut self, i: usize) -> &mut Value {
        match self {
            Value::Array(a) => &mut a[i],
            Value::Object(o) => &mut o[i],
            _ => panic!("attempted to mutably index non-indexable Value object with usize"),
        }
    }
}

impl IndexMut<&str> for Value {
    fn index_mut(&mut self, i: &str) -> &mut Value {
        match self {
            Value::Object(o) => {
                if o.contains_key(i) {
                    &mut o[i]
                } else {
                    o.insert(i.to_string(), Value::Null);
                    &mut o[i]
                }
            }
            _ => panic!("attempted to mutably index non-indexable Value object with string"),
        }
    }
}

impl From<f32> for Value {
    fn from(x: f32) -> Self {
        Self::Number(Number::from(x as f64))
    }
}

impl From<f64> for Value {
    fn from(x: f64) -> Self {
        Self::Number(Number::from(x))
    }
}

impl From<i8> for Value {
    fn from(i: i8) -> Self {
        Self::Number(Number::from(i as i64))
    }
}

impl From<i16> for Value {
    fn from(i: i16) -> Self {
        Self::Number(Number::from(i as i64))
    }
}

impl From<i32> for Value {
    fn from(i: i32) -> Self {
        Self::Number(Number::from(i as i64))
    }
}

impl From<i64> for Value {
    fn from(i: i64) -> Self {
        Self::Number(Number::from(i))
    }
}

impl From<u8> for Value {
    fn from(i: u8) -> Self {
        Self::Number(Number::from(i as i64))
    }
}

impl From<u16> for Value {
    fn from(i: u16) -> Self {
        Self::Number(Number::from(i as i64))
    }
}

impl From<u32> for Value {
    fn from(i: u32) -> Self {
        Self::Number(Number::from(i as i64))
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Self::String(s.to_string())
    }
}

impl From<&String> for Value {
    fn from(s: &String) -> Self {
        Self::String(s.clone())
    }
}

impl From<&[Value]> for Value {
    fn from(a: &[Value]) -> Self {
        Self::Array(a.to_vec())
    }
}

impl From<&HashMap<String, Value>> for Value {
    fn from(h: &HashMap<String, Value>) -> Self {
        let mut map = IndexMap::new();
        for (k, v) in h {
            map.insert(k.to_string(), v.clone());
        }
        Self::Object(map)
    }
}

impl From<&IndexMap<String, Value>> for Value {
    fn from(m: &IndexMap<String, Value>) -> Self {
        Self::Object(m.clone())
    }
}

impl From<&JsonValue> for Value {
    fn from(v: &JsonValue) -> Self {
        match v {
            JsonValue::Null => Self::Null,
            JsonValue::Bool(b) => Self::Boolean(*b),
            JsonValue::Number(n) => {
                if n.to_string().contains('.') {
                    Self::Number(Number::from(n.as_f64().unwrap()))
                } else {
                    Self::Number(Number::from(n.as_i64().unwrap()))
                }
            }
            JsonValue::String(s) => Self::String(s.clone()),
            JsonValue::Array(a) => {
                let mut v = Array::new();
                for e in a {
                    v.push(Self::from(e));
                }
                Self::Array(v)
            }
            JsonValue::Object(o) => {
                let mut m = Object::new();
                for (k, v) in o {
                    m.insert(k.clone(), Self::from(v));
                }
                Self::Object(m)
            }
        }
    }
}

impl TryFrom<&Value> for String {
    type Error = anyhow::Error;

    fn try_from(v: &Value) -> Result<Self> {
        match v {
            Value::String(s) => Ok(s.clone()),
            _ => err!(CESRError::Conversion("could not convert value to string".to_string())),
        }
    }
}

impl TryFrom<&Value> for bool {
    type Error = anyhow::Error;

    fn try_from(v: &Value) -> Result<Self> {
        match v {
            Value::Boolean(b) => Ok(*b),
            _ => err!(CESRError::Conversion("could not convert value to bool".to_string())),
        }
    }
}

impl TryFrom<&Value> for i64 {
    type Error = anyhow::Error;

    fn try_from(v: &Value) -> Result<Self> {
        match v {
            Value::Number(n) => {
                if !n.float {
                    Ok(n.i)
                } else {
                    Ok(n.f as i64)
                }
            }
            _ => err!(CESRError::Conversion("could not convert value to integer".to_string())),
        }
    }
}

impl TryFrom<&Value> for f64 {
    type Error = anyhow::Error;

    fn try_from(v: &Value) -> Result<Self> {
        match v {
            Value::Number(n) => {
                if n.float {
                    Ok(n.f)
                } else {
                    Ok(n.i as f64)
                }
            }
            _ => err!(CESRError::Conversion("could not convert value to float".to_string())),
        }
    }
}

impl TryFrom<&Value> for Vec<Value> {
    type Error = anyhow::Error;

    fn try_from(v: &Value) -> Result<Self> {
        match v {
            Value::Array(a) => Ok(a.clone()),
            _ => err!(CESRError::Conversion("could not convert value to array".to_string())),
        }
    }
}

impl TryFrom<&Value> for IndexMap<String, Value> {
    type Error = anyhow::Error;

    fn try_from(v: &Value) -> Result<Self> {
        match v {
            Value::Object(o) => Ok(o.clone()),
            _ => err!(CESRError::Conversion("could not convert value to map".to_string())),
        }
    }
}

#[macro_export(local_inner_macros)]
macro_rules! dat {
    // arrays

    // Done with trailing comma.
    (@array [$($elems:expr,)*]) => {
        data_internal_vec![$($elems,)*]
    };

    // Done without trailing comma.
    (@array [$($elems:expr),*]) => {
        data_internal_vec![$($elems),*]
    };

    // Next element is `null`.
    (@array [$($elems:expr,)*] null $($rest:tt)*) => {
        dat!(@array [$($elems,)* dat!(null)] $($rest)*)
    };

    // Next element is `true`.
    (@array [$($elems:expr,)*] true $($rest:tt)*) => {
        dat!(@array [$($elems,)* dat!(true)] $($rest)*)
    };

    // Next element is `false`.
    (@array [$($elems:expr,)*] false $($rest:tt)*) => {
        dat!(@array [$($elems,)* dat!(false)] $($rest)*)
    };

    // Next element is an array.
    (@array [$($elems:expr,)*] [$($array:tt)*] $($rest:tt)*) => {
        dat!(@array [$($elems,)* dat!([$($array)*])] $($rest)*)
    };

    // Next element is a map.
    (@array [$($elems:expr,)*] {$($map:tt)*} $($rest:tt)*) => {
        dat!(@array [$($elems,)* dat!({$($map)*})] $($rest)*)
    };

    // Next element is an expression followed by comma.
    (@array [$($elems:expr,)*] $next:expr, $($rest:tt)*) => {
        dat!(@array [$($elems,)* dat!($next),] $($rest)*)
    };

    // Last element is an expression with no trailing comma.
    (@array [$($elems:expr,)*] $last:expr) => {
        dat!(@array [$($elems,)* dat!($last)])
    };

    // Comma after the most recent element.
    (@array [$($elems:expr),*] , $($rest:tt)*) => {
        dat!(@array [$($elems,)*] $($rest)*)
    };

    // Unexpected token after most recent element.
    (@array [$($elems:expr),*] $unexpected:tt $($rest:tt)*) => {
        data_unexpected!($unexpected)
    };

    // objects

    // Done.
    (@object $object:ident () () ()) => {};

    // Insert the current entry followed by trailing comma.
    (@object $object:ident [$($key:tt)+] ($value:expr) , $($rest:tt)*) => {
        let _ = $object.insert(($($key)+).into(), $value);
        dat!(@object $object () ($($rest)*) ($($rest)*));
    };

    // Current entry followed by unexpected token.
    (@object $object:ident [$($key:tt)+] ($value:expr) $unexpected:tt $($rest:tt)*) => {
        data_unexpected!($unexpected);
    };

    // Insert the last entry without trailing comma.
    (@object $object:ident [$($key:tt)+] ($value:expr)) => {
        let _ = $object.insert(($($key)+).into(), $value);
    };

    // Next value is `null`.
    (@object $object:ident ($($key:tt)+) (: null $($rest:tt)*) $copy:tt) => {
        dat!(@object $object [$($key)+] (dat!(null)) $($rest)*);
    };

    // Next value is `true`.
    (@object $object:ident ($($key:tt)+) (: true $($rest:tt)*) $copy:tt) => {
        dat!(@object $object [$($key)+] (dat!(true)) $($rest)*);
    };

    // Next value is `false`.
    (@object $object:ident ($($key:tt)+) (: false $($rest:tt)*) $copy:tt) => {
        dat!(@object $object [$($key)+] (dat!(false)) $($rest)*);
    };

    // Next value is an array.
    (@object $object:ident ($($key:tt)+) (: [$($array:tt)*] $($rest:tt)*) $copy:tt) => {
        dat!(@object $object [$($key)+] (dat!([$($array)*])) $($rest)*);
    };

    // Next value is a map.
    (@object $object:ident ($($key:tt)+) (: {$($map:tt)*} $($rest:tt)*) $copy:tt) => {
        dat!(@object $object [$($key)+] (dat!({$($map)*})) $($rest)*);
    };

    // Next value is an expression followed by comma.
    (@object $object:ident ($($key:tt)+) (: $value:expr , $($rest:tt)*) $copy:tt) => {
        dat!(@object $object [$($key)+] (dat!($value)) , $($rest)*);
    };

    // Last value is an expression with no trailing comma.
    (@object $object:ident ($($key:tt)+) (: $value:expr) $copy:tt) => {
        dat!(@object $object [$($key)+] (dat!($value)));
    };

    // Missing value for last entry. Trigger a reasonable error message.
    (@object $object:ident ($($key:tt)+) (:) $copy:tt) => {
        // "unexpected end of macro invocation"
        dat!();
    };

    // Missing colon and value for last entry. Trigger a reasonable error
    // message.
    (@object $object:ident ($($key:tt)+) () $copy:tt) => {
        // "unexpected end of macro invocation"
        dat!();
    };

    // Misplaced colon. Trigger a reasonable error message.
    (@object $object:ident () (: $($rest:tt)*) ($colon:tt $($copy:tt)*)) => {
        // Takes no arguments so "no rules expected the token `:`".
        data_unexpected!($colon);
    };

    // Found a comma inside a key. Trigger a reasonable error message.
    (@object $object:ident ($($key:tt)*) (, $($rest:tt)*) ($comma:tt $($copy:tt)*)) => {
        // Takes no arguments so "no rules expected the token `,`".
        data_unexpected!($comma);
    };

    // Key is fully parenthesized. This avoids clippy double_parens false
    // positives because the parenthesization may be necessary here.
    (@object $object:ident () (($key:expr) : $($rest:tt)*) $copy:tt) => {
        dat!(@object $object ($key) (: $($rest)*) (: $($rest)*));
    };

    // Refuse to absorb colon token into key expression.
    (@object $object:ident ($($key:tt)*) (: $($unexpected:tt)+) $copy:tt) => {
        data_expect_expr_comma!($($unexpected)+);
    };

    // Munch a token into the current key.
    (@object $object:ident ($($key:tt)*) ($tt:tt $($rest:tt)*) $copy:tt) => {
        dat!(@object $object ($($key)* $tt) ($($rest)*) ($($rest)*));
    };

    // core logic

    (null) => {
        $crate::data::Value::Null
    };

    (true) => {
        $crate::data::Value::Boolean(true)
    };

    (false) => {
        $crate::data::Value::Boolean(false)
    };

    ([]) => {
        $crate::data::Value::Array($crate::data::Array::new())
    };

    ([ $($tt:tt)+ ]) => {{
        dat!(@array [] $($tt)+)
    }};

    ({}) => {
        $crate::data::Value::Object($crate::data::Object::new())
    };

    ({ $($tt:tt)+ }) => {{
        let mut object = $crate::data::Object::new();
        dat!(@object object () ($($tt)+) ($($tt)+));
        $crate::data::Value::Object(object)
    }};

    ($other:expr) => {
        $crate::data::Value::from($other)
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! data_internal_vec {
    ($($content:tt)*) => {{
        $crate::data::Value::Array(vec![$($content)*])
    }};
}

#[macro_export]
#[doc(hidden)]
macro_rules! data_unexpected {
    () => {};
}

#[macro_export]
#[doc(hidden)]
macro_rules! data_expect_expr_comma {
    ($e:expr , $($tt:tt)*) => {};
}

pub use dat;

#[cfg(test)]
mod test {
    use crate::data::{dat, Value};
    use indexmap::IndexMap;

    #[test]
    fn macros() {
        let x: i64 = -1234567890;
        let s = "string".to_string();

        let mut d = dat!({
            "thing": 2,
            "other thing": [&s, 1.666, x, true, {"nested array": [{}, []]}],
            "last thing": null
        });

        // to_json()
        assert_eq!(
            d.to_json().unwrap(),
            "{\"thing\":2,\"other thing\":[\"string\",1.666,-1234567890,true,{\"nested array\":[{},[]]}],\"last thing\":null}"
        );

        // query/indexing
        assert_eq!(d["thing"], d[0]); // we can index into an object with an integer or string key
        assert_ne!(d["thing"], d[1]);

        // display
        assert_eq!(format!("{}", d["thing"]), "2");

        // data extraction
        assert_eq!(d["last thing"], Value::Null);
        assert!(d["other thing"][3].to_bool().unwrap());
        assert_eq!(d["thing"].to_i64().unwrap(), 2);
        assert_eq!(d["other thing"][1].to_f64().unwrap(), 1.666);
        assert_eq!(d["other thing"][0].to_string().unwrap(), "string");
        assert_eq!(d["other thing"][4]["nested array"][1].to_vec().unwrap(), vec![]);
        assert_eq!(
            d["other thing"][4]["nested array"][0].to_map().unwrap(),
            indexmap::IndexMap::new()
        );

        // mutability
        d["thing"] = dat!({"something more complex": {"key": 987654321 }});
        d[1][1] = dat!(true);
        assert_eq!(
            d.to_json().unwrap(),
            "{\"thing\":{\"something more complex\":{\"key\":987654321}},\"other thing\":[\"string\",true,-1234567890,true,{\"nested array\":[{},[]]}],\"last thing\":null}"
        );

        // serde_json parsing interop
        let v: serde_json::Value = serde_json::from_str(&d.to_json().unwrap()).unwrap();
        let d2 = Value::from(&v);
        assert_eq!(d.to_json().unwrap(), d2.to_json().unwrap());
    }

    #[test]
    fn value() {
        assert!(dat!({}).to_json().is_ok());
        // assert!(dat!({}).to_cesr().is_err());
        // assert!(dat!({}).to_cesrb().is_err());

        let array: &[Value] = &[];
        let mut hash_map = std::collections::HashMap::<String, Value>::new();
        hash_map.insert("test".to_string(), dat!(true));
        let d = dat!({
            "f32": 0_f32,
            "f64": 0_f64,
            "i8": 0_i8,
            "i16": 0_i16,
            "i32": 0_i32,
            "i64": 0_i64,
            "u8": 0_u8,
            "u16": 0_u16,
            "u32": 0_u32,
            "hash map": &hash_map,
            "array": array,
        });
        let json = d.to_json().unwrap();
        assert_eq!(json, "{\"f32\":0.0,\"f64\":0.0,\"i8\":0,\"i16\":0,\"i32\":0,\"i64\":0,\"u8\":0,\"u16\":0,\"u32\":0,\"hash map\":{\"test\":true},\"array\":[]}");
        assert!(d[0].to_bool().is_err());
        assert!(d["hash map"].to_i64().is_err());
        assert!(d["hash map"].to_f64().is_err());
        assert!(d["f32"].to_vec().is_err());
        assert!(d["f32"].to_map().is_err());
        assert!(d["f64"].to_i64().is_err());
        assert!(d["i64"].to_f64().is_err());

        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let d2 = Value::from(&v);
        assert_eq!(json, d2.to_json().unwrap());
    }

    #[test]
    fn try_from() {
        let string = dat!("string");
        let boolean = dat!(false);
        let int64 = dat!(3);
        let float64 = dat!(6.7);
        let vector = dat!([]);
        let map = dat!({});

        assert!(String::try_from(&string).is_ok());
        assert!(String::try_from(&boolean).is_err());
        assert!(bool::try_from(&boolean).is_ok());
        assert!(bool::try_from(&string).is_err());
        assert!(i64::try_from(&int64).is_ok());
        assert!(i64::try_from(&float64).is_ok());
        assert!(i64::try_from(&string).is_err());
        assert!(f64::try_from(&float64).is_ok());
        assert!(f64::try_from(&int64).is_ok());
        assert!(f64::try_from(&string).is_err());
        assert!(Vec::try_from(&vector).is_ok());
        assert!(Vec::try_from(&string).is_err());
        assert!(IndexMap::try_from(&map).is_ok());
        assert!(IndexMap::try_from(&string).is_err());
    }
}
