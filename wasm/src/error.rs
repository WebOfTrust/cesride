use cesride_core::Error as CesrError;
use cesride_core::Result as CesrResult;
use js_sys::{Error as JsError, JsString};
use wasm_bindgen::{prelude::*, JsCast};

// Allows conversion of CesrError to javascript error
pub(crate) trait JsResult<T> {
    fn as_js(self) -> Result<T, JsError>;
}

impl<T> JsResult<T> for CesrResult<T> {
    fn as_js(self) -> Result<T, JsError> {
        self.map_err(|e| JsError::new(&e.to_string()))
    }
}

// Alows convertion of javascript error to CesrError
pub(crate) trait FromJsResult<T> {
    fn from_js(self) -> CesrResult<T>;
}

impl<T> FromJsResult<T> for Result<T, JsValue> {
    fn from_js(self) -> CesrResult<T> {
        self.map_err(|e| {
            // String was thrown
            if let Some(e) = e.dyn_ref::<JsString>() {
                let msg = e.to_string();
                return CesrError::General(msg.into()).into();
            }

            // Error instance was thrown
            if let Some(e) = e.dyn_ref::<JsError>() {
                let message = e.message().as_string().unwrap_or(format!("{:?}", e));
                return match e.name().as_string().as_deref() {
                    Some("CesrErrorCommon") => CesrError::InvalidVarSize(message),
                    Some(msg) => CesrError::General(msg.to_string()),
                    _ => CesrError::General("Unknown error".to_string()),
                }
                .into();
            }

            CesrError::General("Unknown error".to_string()).into()
        })
    }
}
