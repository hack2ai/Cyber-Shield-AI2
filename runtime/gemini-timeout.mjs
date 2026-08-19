import { GoogleGenerativeAI } from '@google/generative-ai';

export const GEMINI_TIMEOUT_MS = 5_000;

export function withTimeout(promise, timeoutMs = GEMINI_TIMEOUT_MS, message = 'Gemini request timed out') {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

const originalGetGenerativeModel = GoogleGenerativeAI.prototype.getGenerativeModel;
GoogleGenerativeAI.prototype.getGenerativeModel = function (...args) {
  const model = originalGetGenerativeModel.apply(this, args);
  const originalGenerateContent = model.generateContent.bind(model);
  model.generateContent = (...generateArgs) => withTimeout(originalGenerateContent(...generateArgs));
  return model;
};
