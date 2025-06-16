
import { GoogleGenAI, GenerateContentResponse, Part } from "@google/genai";
import { GEMINI_MODEL_TEXT } from '../constants';
import { GroundingChunk } from "../types";

const API_KEY = process.env.API_KEY;

let ai: GoogleGenAI | null = null;
if (API_KEY) {
  ai = new GoogleGenAI({ apiKey: API_KEY });
} else {
  console.warn("API_KEY environment variable is not set. Gemini API features will be disabled.");
}

export const geminiService = {
  explainTerm: async (term: string): Promise<{ explanation: string; groundingChunks?: GroundingChunk[] }> => {
    if (!ai) {
      throw new Error("Gemini API key not configured. Please set the API_KEY environment variable.");
    }
    if (!term.trim()) {
      throw new Error("Term cannot be empty.");
    }

    const prompt = `Explain the cryptographic term "${term}" in a concise and easy-to-understand way for someone new to cryptography. If relevant, mention its common uses or significance. Use Google Search for up-to-date information if needed.`;

    try {
      const response: GenerateContentResponse = await ai.models.generateContent({
        model: GEMINI_MODEL_TEXT,
        contents: [{ role: "user", parts: [{text: prompt} as Part] }],
        config: {
          tools: [{googleSearch: {}}], // Enable Google Search grounding
        }
      });
      
      const explanation = response.text;
      const groundingMetadata = response.candidates?.[0]?.groundingMetadata;
      let groundingChunks: GroundingChunk[] | undefined = undefined;

      if (groundingMetadata && groundingMetadata.groundingChunks && groundingMetadata.groundingChunks.length > 0) {
        groundingChunks = groundingMetadata.groundingChunks
          .filter(chunk => chunk.web && chunk.web.uri && chunk.web.title) // Ensure essential web data is present
          .map(chunk => ({
             web: {
               uri: chunk.web.uri,
               title: chunk.web.title,
             }
           }));
      }
      
      return { explanation, groundingChunks };

    } catch (error) {
      console.error("Error calling Gemini API:", error);
      if (error instanceof Error) {
        if (error.message.includes("API key not valid")) {
             throw new Error("Invalid Gemini API Key. Please check your API_KEY environment variable.");
        }
         throw new Error(`Failed to get explanation from Gemini API: ${error.message}`);
      }
      throw new Error("An unknown error occurred while fetching explanation from Gemini API.");
    }
  },
};
