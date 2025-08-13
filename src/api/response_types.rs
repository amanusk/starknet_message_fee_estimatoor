use crate::fee_estimator::FeeEstimationSummary;
use serde::{Deserialize, Serialize};

/// Standardized API response for all RPC methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse {
    /// Success data - contains the FeeEstimationSummary when successful
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<FeeEstimationSummary>,

    /// Error information when the request fails
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

impl ApiResponse {
    /// Create a successful response
    pub fn success(summary: FeeEstimationSummary) -> Self {
        Self {
            result: Some(summary),
            error: None,
        }
    }

    /// Create an error response
    pub fn error(error: ApiError) -> Self {
        Self {
            result: None,
            error: Some(error),
        }
    }
}

/// Comprehensive error types that can occur during fee estimation
/// Follows OpenRPC specification format with code, message, and data fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    /// Error code for programmatic handling (OpenRPC spec)
    pub code: ApiErrorCode,

    /// Human-readable error message (OpenRPC spec)
    pub message: String,

    /// Additional error data (OpenRPC spec)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

impl ApiError {
    /// Create a new API error
    pub fn new(code: ApiErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Create a new API error with data
    pub fn with_data(
        code: ApiErrorCode,
        message: impl Into<String>,
        data: impl Into<String>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            data: Some(data.into()),
        }
    }

    /// Create a new API error with details (alias for with_data for backward compatibility)
    pub fn with_details(
        code: ApiErrorCode,
        message: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self::with_data(code, message, details)
    }
}

/// Specific error codes for different types of failures
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiErrorCode {
    /// Invalid input format - malformed JSON, wrong data types, etc.
    InvalidInputFormat,

    /// Invalid unsigned transaction - missing required fields, invalid addresses, etc.
    InvalidUnsignedTransaction,

    /// Invalid signed transaction - malformed transaction data, invalid signatures, etc.
    InvalidSignedTransaction,

    /// Failed to simulate transaction - network issues, transaction reverts, etc.
    TransactionSimulationFailed,

    /// Failed to estimate fee - Starknet RPC issues, invalid message data, etc.
    FeeEstimationFailed,

    /// Generic error for unexpected failures
    InternalError,
}

impl ApiErrorCode {
    /// Get the default message for each error code
    pub fn default_message(&self) -> &'static str {
        match self {
            ApiErrorCode::InvalidInputFormat => "Invalid input format",
            ApiErrorCode::InvalidUnsignedTransaction => "Invalid unsigned transaction",
            ApiErrorCode::InvalidSignedTransaction => "Invalid signed transaction",
            ApiErrorCode::TransactionSimulationFailed => "Failed to simulate transaction",
            ApiErrorCode::FeeEstimationFailed => "Failed to estimate fee",
            ApiErrorCode::InternalError => "Internal server error",
        }
    }
}

impl From<ApiErrorCode> for ApiError {
    fn from(code: ApiErrorCode) -> Self {
        Self::new(code.clone(), code.default_message())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fee_estimator::{FeeEstimationSummary, MessageFeeEstimate};
    use starknet::core::types::Felt;

    #[test]
    fn test_api_response_success() {
        let summary = FeeEstimationSummary {
            total_messages: 1,
            successful_estimates: 1,
            failed_estimates: 0,
            total_fee_wei: 1000000000000000000,
            total_fee_eth: 1.0,
            individual_estimates: vec![MessageFeeEstimate {
                l2_address: Felt::ONE,
                selector: Felt::TWO,
                gas_consumed: 21000,
                gas_price: 20000000000,
                overall_fee: 1000000000000000000,
                unit: "WEI".to_string(),
            }],
            errors: vec![],
        };

        let response = ApiResponse::success(summary.clone());

        assert!(response.result.is_some());
        assert!(response.error.is_none());
        assert_eq!(response.result.unwrap().total_messages, 1);
    }

    #[test]
    fn test_api_response_error() {
        let error = ApiError::new(ApiErrorCode::InvalidInputFormat, "Invalid JSON");
        let response = ApiResponse::error(error);

        assert!(response.result.is_none());
        assert!(response.error.is_some());

        let err = response.error.unwrap();
        assert!(matches!(err.code, ApiErrorCode::InvalidInputFormat));
        assert_eq!(err.message, "Invalid JSON");
    }

    #[test]
    fn test_api_error_with_data() {
        let error = ApiError::with_data(
            ApiErrorCode::InvalidUnsignedTransaction,
            "Missing required field",
            "The 'from' field is required for unsigned transactions",
        );

        assert!(matches!(
            error.code,
            ApiErrorCode::InvalidUnsignedTransaction
        ));
        assert_eq!(error.message, "Missing required field");
        assert_eq!(
            error.data.unwrap(),
            "The 'from' field is required for unsigned transactions"
        );
    }

    #[test]
    fn test_api_error_with_details_backward_compatibility() {
        let error = ApiError::with_details(
            ApiErrorCode::InvalidUnsignedTransaction,
            "Missing required field",
            "The 'from' field is required for unsigned transactions",
        );

        assert!(matches!(
            error.code,
            ApiErrorCode::InvalidUnsignedTransaction
        ));
        assert_eq!(error.message, "Missing required field");
        assert_eq!(
            error.data.unwrap(),
            "The 'from' field is required for unsigned transactions"
        );
    }

    #[test]
    fn test_api_error_from_code() {
        let error = ApiError::from(ApiErrorCode::FeeEstimationFailed);

        assert!(matches!(error.code, ApiErrorCode::FeeEstimationFailed));
        assert_eq!(error.message, "Failed to estimate fee");
        assert!(error.data.is_none());
    }

    #[test]
    fn test_api_error_code_default_messages() {
        assert_eq!(
            ApiErrorCode::InvalidInputFormat.default_message(),
            "Invalid input format"
        );
        assert_eq!(
            ApiErrorCode::InvalidUnsignedTransaction.default_message(),
            "Invalid unsigned transaction"
        );
        assert_eq!(
            ApiErrorCode::InvalidSignedTransaction.default_message(),
            "Invalid signed transaction"
        );
        assert_eq!(
            ApiErrorCode::TransactionSimulationFailed.default_message(),
            "Failed to simulate transaction"
        );
        assert_eq!(
            ApiErrorCode::FeeEstimationFailed.default_message(),
            "Failed to estimate fee"
        );
        assert_eq!(
            ApiErrorCode::InternalError.default_message(),
            "Internal server error"
        );
    }

    #[test]
    fn test_serialization() {
        let summary = FeeEstimationSummary {
            total_messages: 1,
            successful_estimates: 1,
            failed_estimates: 0,
            total_fee_wei: 1000000000000000000,
            total_fee_eth: 1.0,
            individual_estimates: vec![],
            errors: vec![],
        };

        let response = ApiResponse::success(summary);
        let json = serde_json::to_string(&response).unwrap();

        // Should not include null fields
        assert!(!json.contains("\"error\":null"));
        assert!(json.contains("\"result\""));
    }

    #[test]
    fn test_error_serialization() {
        let error = ApiError::new(ApiErrorCode::InvalidInputFormat, "Test error");
        let response = ApiResponse::error(error);
        let json = serde_json::to_string(&response).unwrap();

        // Should not include null fields
        assert!(!json.contains("\"result\":null"));
        assert!(json.contains("\"error\""));
        assert!(json.contains("\"invalid_input_format\""));
    }
}
