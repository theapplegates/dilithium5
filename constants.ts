
export const PRIMARY_SIGNING_ALGORITHM = "Dilithium5";
export const ENCRYPTION_SUBKEY_ALGORITHM = "Kyber1024";

export const GEMINI_MODEL_TEXT = "gemini-2.5-flash-preview-04-17";

// Mock API Key - In a real application, this would come from process.env.API_KEY
// For this environment, we assume process.env.API_KEY is set.
// If not set, the Gemini helper will show an error.
export const MOCK_API_KEY_INFO = "process.env.API_KEY should be set in the environment.";

export const DEBOUNCE_DELAY = 300; // ms
