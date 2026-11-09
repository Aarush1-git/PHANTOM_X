import "@testing-library/jest-dom";

// Mock ResizeObserver for Recharts / React Flow in JSDOM
global.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};

